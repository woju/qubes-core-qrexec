#!/usr/bin/env python3
#
# The Qubes OS Project, https://www.qubes-os.org/
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
# Copyright (C) 2021 Demi Marie Obenour <demi@invisiblethingslab.com>
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

'''policy.Eval

This service allows qrexec policy to be evaluated outside of dom0.  One user of
it is the GUI daemon, which needs to evaluate ``qubes.ClipboardPaste``.
'''

import sys
import socket

from .. import POLICYSOCKET

def main(args=None):
    untrusted_arg = sys.stdin.buffer.read(64)
    if len(untrusted_arg) > 63:
        return 2
    try:
        split = untrusted_arg.index(b'\0')
        if split < 1 or split > 31:
            return 2
        untrusted_source = untrusted_arg[:split]
        untrusted_target = untrusted_arg[split + 1:]
        # these throw exceptions if the domain name is not valid
        utils.sanitize_domain_name(untrusted_source, True)
        utils.sanitize_domain_name(untrusted_target, True)
    except ValueError:
        return 2
    source, target = untrusted_source, untrusted_target
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_socket.connect(POLICYSOCKET)
    client_socket.sendall(b'''\
source=%s
intended_target=%s
service_and_arg=%s
assume_yes_for_ask=yes
just_evaluate=yes
domain_id=-1
process_ident=-1
''' % (source, target, os.environ['QREXEC_SERVICE_ARGUMENT'].decode('ascii', 'strict')))
    client_socket.shutdown(socket.SHUT_WR)
    return_data = client_socket.makefile('rb').read()
    if return_data == b'result=allow\n':
        return 0
    elif return_data == b'result=deny\n':
        return 1
    else:
        raise AssertionError('Bad response from policy daemon')

if __name__ == '__main__':
    sys.exit(main())
