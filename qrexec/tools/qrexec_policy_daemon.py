#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2019 Marta Marczykowska-Górecka
#                               <marmarta@invisiblethingslab.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <https://www.gnu.org/licenses/>.
#

import argparse
import functools
import pathlib
import asyncio
import logging
import os

from .qrexec_policy_exec import handle_request
from .. import POLICYPATH, POLICYSOCKET
from ..policy.utils import PolicyCache

argparser = argparse.ArgumentParser(description='Evaluate qrexec policy daemon')

argparser.add_argument('--policy-path',
    type=pathlib.Path, default=POLICYPATH,
    help='Use alternative policy path')
argparser.add_argument('--socket-path',
    type=pathlib.Path, default=POLICYSOCKET,
    help='Use alternative policy socket path')

REQUIRED_REQUEST_ARGUMENTS = ('domain_id', 'source', 'intended_target',
                              'service_and_arg', 'process_ident')

OPTIONAL_REQUEST_ARGUMENTS = ('assume_yes_for_ask', 'just_evaluate')

ALLOWED_REQUEST_ARGUMENTS = REQUIRED_REQUEST_ARGUMENTS + \
                            OPTIONAL_REQUEST_ARGUMENTS


async def handle_client_connection(log, policy_cache,
                                   reader, writer):

    args = {}

    try:
        while True:
            line = await reader.readline()
            line = line.decode('ascii').rstrip('\n')

            if not line:
                break

            argument, value = line.split('=', 1)
            if argument in args:
                log.error(
                    'error parsing policy request: '
                    'duplicate argument {}'.format(argument))
                return
            if argument not in ALLOWED_REQUEST_ARGUMENTS:
                log.error(
                    'error parsing policy request: unknown argument {}'.format(
                        argument))
                return

            if argument in ('assume_yes_for_ask', 'just_evaluate'):
                if value == 'yes':
                    value = True
                elif value == 'no':
                    value = False
                else:
                    log.error(
                        'error parsing policy request: invalid bool value '
                        '{} for argument {}'.format(value, argument))
                    return

            args[argument] = value

        if not all(arg in args for arg in REQUIRED_REQUEST_ARGUMENTS):
            log.error(
                'error parsing policy request: required argument missing')
            return

        result = await handle_request(**args, log=log,
                                      policy_cache=policy_cache)

        writer.write(b"result=allow\n" if result == 0 else b"result=deny\n")
        await writer.drain()

    finally:
        writer.close()

async def handle_qrexec_connection(log, policy_cache,
                                   reader, writer):

    args = {}

    try:
        untrusted_data = await reader.read(65536)
        if len(untrusted_data) > 65535:
            log.error('Request length too long: %d', len(data))
            return
        try:
            index_1 = untrusted_data.index(b'\0')
            # This has already been validated by qrexec, so at least parts of
            # it can be trusted.
            qrexec_command_with_arg = untrusted_data[:index_1].decode('ascii', 'strict')
            # This part is still untrusted
            untrusted_data = untrusted_data[index_1 + 1:].decode('ascii', 'strict')
            # qrexec guarantees this will work
            qrexec_command_with_arg = qrexec_command_with_arg.split(' ')[0]
            index_1 = qrexec_command_with_arg.index('+')
            # The service used to invoke us
            our_service_name = qrexec_command[:index_1]
            # The service we are being queried for
            qrexec_arg = qrexec_command_with_arg[index_1 + 1:]

            if len(untrusted_data) > 63:
                log.error('Request data too long: %d', len(untrusted_data))
                return
            split = untrusted_data.index('\0')
            if split < 1 or split > 31:
                log.error('Invalid data from qube')
                return
            untrusted_source = untrusted_data[:split]
            untrusted_target = untrusted_data[split + 1:]

            # these throw exceptions if the domain name is not valid
            utils.sanitize_service_name(qrexec_arg, True)
            utils.sanitize_domain_name(untrusted_source, True)
            utils.sanitize_domain_name(untrusted_target, True)
            source, intended_target = untrusted_source, untrusted_target
        except (ValueError, UnicodeError):
            log.error('Invalid data from qube')
            return

        result = await handle_request(
                source=source,
                intended_target=intended_target,
                domain_id = -1,
                process_ident = -1
                assume_yes_for_ask=True,
                just_evaluate=True,
                log=log,
                policy_cache=policy_cache)

        writer.write(b"result=allow\n" if result == 0 else b"result=deny\n")
        await writer.drain()

    finally:
        writer.close()


async def start_serving(args=None):
    args = argparser.parse_args(args)

    logging.basicConfig(format="%(message)s")
    log = logging.getLogger('policy')
    log.setLevel(logging.INFO)

    policy_cache = PolicyCache(args.policy_path)
    policy_cache.initialize_watcher()
    policy_server = await asyncio.create_unix_server(
        functools.partial(
            handle_client_connection, log, policy_cache),
        path=args.socket_path)

    eval_server = await asyncio.create_unix_server(
        functools.partial(
            handle_qrexec_connection, log, policy_cache),
        path='/etc/qubes-rpc/policy.Eval')
    os.chmod(args.socket_path, 0o660)

    await asyncio.wait([server.wait_closed() for server in (policy_server, eval_server)])


def main(args=None):
    # pylint: disable=no-member
    # due to travis' limitations we have to use python 3.5 in pylint
    asyncio.run(start_serving(args))


if __name__ == '__main__':
    main()
