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
            # Qrexec guarantees that this will be present
            service_descriptor_len = untrusted_data.index(b'\0')
            # This has already been validated by qrexec, so at least parts of
            # it can be trusted.
            service_descriptor = untrusted_data[:service_descriptor_len]
            qrexec_command_with_arg = service_descriptor[:service_descriptor.index(b' ')]
            qrexec_command_len = qrexec_command_with_arg.find(b'+')
            if qrexec_command_len <= 0:
                if qrexec_command_len:
                    log.warning('No service specified in policy query')
                else:
                    log.error('Invoked via an empty service name?')
                return
            # The service we are being queried for
            service_queried = qrexec_command_with_arg[qrexec_command_len + 1:]
            if not service_queried:
                log.warning('Empty string is not a valid service')

            ### SANITIZE BEGIN
            untrusted_data = untrusted_data[service_descriptor_len + 1:]

            if len(untrusted_data) > 63:
                log.warning('Request data too long: %d', len(untrusted_data))
                return
            split = untrusted_data.find(b'\0')
            if not (1 <= split <= 31):
                log.warning('Invalid data from qube')
                return
            untrusted_source = untrusted_data[:split].decode('ascii', 'strict')
            untrusted_target = untrusted_data[split + 1:].decode('ascii', 'strict')
            if not (1 <= len(untrusted_target) <= 31):
                log.warning('Invalid data from qube')
                return

            # these throw exceptions if the domain name is not valid
            utils.sanitize_service_name(qrexec_arg, True)
            utils.sanitize_domain_name(untrusted_source, True)
            utils.sanitize_domain_name(untrusted_target, True)
            ### SANITIZE END
            source, intended_target = untrusted_source, untrusted_target
        except (ValueError, UnicodeError):
            log.warning('Invalid data from qube')
            return

        result = await handle_request(
                source=source,
                intended_target=intended_target,
                service_and_arg=service_queried.decode('ascii', 'strict'),
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
