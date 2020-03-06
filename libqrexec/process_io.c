/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2020 Paweł Marczewski <pawel@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libqrexec-utils.h"

static _Noreturn void handle_vchan_error(const char *op)
{
    fprintf(stderr, "Error while vchan %s, exiting\n", op);
    exit(1);
}

int process_io(const struct process_io_request *req) {
    libvchan_t *vchan = req->vchan;
    int stdin_fd = req->stdin_fd;
    int stdout_fd = req->stdout_fd;
    int stderr_fd = req->stderr_fd;
    struct buffer *stdin_buf = req->stdin_buf;

    bool is_service = req->is_service;
    bool replace_chars_stdout = req->replace_chars_stdout;
    bool replace_chars_stderr = req->replace_chars_stderr;
    int data_protocol_version = req->data_protocol_version;

    pid_t local_pid = req->local_pid;
    volatile sig_atomic_t *sigchld = req->sigchld;
    volatile sig_atomic_t *sigusr1 = req->sigusr1;

    sigset_t selectmask;
    pid_t local_status = -1;
    pid_t remote_status = -1;
    int stdout_msg_type = is_service ? MSG_DATA_STDOUT : MSG_DATA_STDIN;
    bool use_stdio_socket = false;

    fd_set rdset, wrset;
    int vchan_fd;
    int ret, max_fd;
    struct timespec zero_timeout = { 0, 0 };
    struct timespec normal_timeout = { 10, 0 };

    sigemptyset(&selectmask);
    sigaddset(&selectmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &selectmask, NULL);
    sigemptyset(&selectmask);

    set_nonblock(stdin_fd);
    if (stdout_fd != stdin_fd)
        set_nonblock(stdout_fd);
    else if ((stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3)) < 0)
        abort(); // not worth handling running out of file descriptors
    if (stderr_fd >= 0)
        set_nonblock(stderr_fd);

    while(1) {
        /* React to SIGCHLD */
        if (*sigchld) {
            int status;
            if (local_pid > 0 && waitpid(local_pid, &status, WNOHANG > 0)) {
                if (WIFSIGNALED(status))
                    local_status = 128 + WTERMSIG(status);
                else
                    local_status = WEXITSTATUS(status);
                if (stdin_fd >= 0) {
                    /* restore flags */
                    set_block(stdin_fd);
                    if (!local_pid || stdin_fd == 1 ||
                            (shutdown(stdin_fd, SHUT_WR) == -1 &&
                             errno == ENOTSOCK)) {
                        close(stdin_fd);
                    }
                    stdin_fd = -1;
                }
            }
            *sigchld = 0;
        }

        /* if all done, exit the loop */
        if (stdin_fd == -1 && stdout_fd == -1 && stderr_fd == -1) {
            if (is_service) {
                if (!local_pid || local_status >= 0) {
                    /* send exit code and break */
                    if (send_exit_code(vchan, local_pid ? local_status : 0) < 0)
                        handle_vchan_error("exit code");
                    break;
                }
            } else {
                /* if there's no local process, wait for remote end */
                if ((local_pid && local_status >= 0) ||
                    (!local_pid && remote_status >= 0))
                    break;
            }
        }

        /* also if vchan is disconnected (and we processed all the data), there
         * is no sense of processing further data */
        if (!libvchan_data_ready(vchan) &&
                !libvchan_is_open(vchan) &&
                !buffer_len(stdin_buf)) {
            break;
        }

        /* child signaled desire to use single socket for both stdin and stdout */
        if (sigusr1 && *sigusr1) {
            if (stdout_fd != -1) {
                do
                    errno = 0;
                while (dup3(stdin_fd, stdout_fd, O_CLOEXEC) &&
                       (errno == EINTR || errno == EBUSY));
                // other errors are fatal
                if (errno) {
                    fputs("Fatal error from dup3()\n", stderr);
                    abort();
                }
            } else {
                stdout_fd = fcntl(stdin_fd, F_DUPFD_CLOEXEC, 3);
                // all errors are fatal
                if (stdout_fd < 3)
                    abort();
            }
            use_stdio_socket = true;
            *sigusr1 = 0;
        }

        /* otherwise handle the events */
        FD_ZERO(&rdset);
        FD_ZERO(&wrset);
        max_fd = -1;
        vchan_fd = libvchan_fd_for_select(vchan);
        if (libvchan_buffer_space(vchan) > (int)sizeof(struct msg_header)) {
            if (stdout_fd >= 0) {
                FD_SET(stdout_fd, &rdset);
                if (stdout_fd > max_fd)
                    max_fd = stdout_fd;
            }
            if (stderr_fd >= 0) {
                FD_SET(stderr_fd, &rdset);
                if (stderr_fd > max_fd)
                    max_fd = stderr_fd;
            }
        }
        FD_SET(vchan_fd, &rdset);
        if (vchan_fd > max_fd)
            max_fd = vchan_fd;
        /* if we have something buffered for the child process, wake also on
         * writable stdin */
        if (stdin_fd > -1 && buffer_len(stdin_buf)) {
            FD_SET(stdin_fd, &wrset);
            if (stdin_fd > max_fd)
                max_fd = stdin_fd;
        }
        if (!buffer_len(stdin_buf) && libvchan_data_ready(vchan) > 0) {
            /* check for other FDs, but exit immediately */
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, &zero_timeout, &selectmask);
        } else
            ret = pselect(max_fd + 1, &rdset, &wrset, NULL, &normal_timeout, &selectmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("pselect");
                /* TODO */
                break;
            }
        }

        /* clear event pending flag */
        if (FD_ISSET(vchan_fd, &rdset)) {
            if (libvchan_wait(vchan) < 0)
                handle_vchan_error("wait");
        }

        /* handle_remote_data will check if any data is available */
        switch (handle_remote_data(
                    vchan, stdin_fd,
                    &remote_status,
                    stdin_buf,
                    data_protocol_version,
                    local_pid && stdin_fd != 1,
                    replace_chars_stdout > 0,
                    replace_chars_stderr > 0)) {
            case REMOTE_ERROR:
                handle_vchan_error("read");
                break;
            case REMOTE_EOF:
                stdin_fd = -1;
                break;
            case REMOTE_EXITED:
                /* remote process exited, no sense in sending more data to it;
                 * be careful to not shutdown socket inherited from parent */
                if (!local_pid || stdout_fd == 0 ||
                        (shutdown(stdout_fd, SHUT_RD) == -1 &&
                         errno == ENOTSOCK)) {
                    close(stdout_fd);
                }
                stdout_fd = -1;
                close(stderr_fd);
                stderr_fd = -1;
                /* if we do not care for any local process, return remote process code */
                if (!is_service && local_pid == 0)
                    return remote_status;
                break;
        }
        if (stdout_fd >= 0 && FD_ISSET(stdout_fd, &rdset)) {
            switch (handle_input(
                        vchan, stdout_fd, stdout_msg_type,
                        data_protocol_version,
                        !use_stdio_socket)) {
                case REMOTE_ERROR:
                    handle_vchan_error("send");
                    break;
                case REMOTE_EOF:
                    stdout_fd = -1;
                    break;
            }
        }
        if (stderr_fd >= 0 && FD_ISSET(stderr_fd, &rdset)) {
            switch (handle_input(
                        vchan, stderr_fd, MSG_DATA_STDERR,
                        data_protocol_version,
                        !use_stdio_socket)) {
                case REMOTE_ERROR:
                    handle_vchan_error("send");
                    break;
                case REMOTE_EOF:
                    stderr_fd = -1;
                    break;
            }
        }
    }
    /* make sure that all the pipes/sockets are closed, so the child process
     * (if any) will know that the connection is terminated */
    if (stdout_fd != -1) {
        /* restore flags */
        set_block(stdout_fd);
        /* be careful to not shutdown socket inherited from parent */
        if (!local_pid || stdout_fd == 0 ||
                (shutdown(stdout_fd, SHUT_RD) == -1 && errno == ENOTSOCK)) {
            close(stdout_fd);
        }
        stdout_fd = -1;
    }
    if (stdin_fd != -1) {
        /* restore flags */
        set_block(stdin_fd);
        /* be careful to not shutdown socket inherited from parent */
        if (!local_pid || stdin_fd == 1 ||
                (shutdown(stdin_fd, SHUT_WR) == -1 && errno == ENOTSOCK)) {
            close(stdin_fd);
        }
        stdin_fd = -1;
    }
    if (stderr_fd != -1) {
        /* restore flags */
        set_block(stderr_fd);
        close(stderr_fd);
        stderr_fd = -1;
    }
    if (!is_service && remote_status >= 0)
        return remote_status;
    return local_pid ? local_status : 0;
}