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

import logging
import logging.handlers
import pathlib
import sys
import os
import asyncio

from .. import DEFAULT_POLICY, POLICYPATH
from .. import exc
from .. import utils
from ..policy import parser
from ..policy.utils import PolicyCache

class JustEvaluateResult(Exception):
    def __init__(self, exit_code):
        super().__init__()
        self.exit_code = exit_code

class JustEvaluateAllowResolution(parser.AllowResolution):
    async def execute(self, caller_ident):
        raise JustEvaluateResult(0)

class AssumeYesForAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        return await self.handle_user_response(
            True, self.request.target).execute(caller_ident)

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
        utls.sanitize_domain_name(untrusted_source, True)
        utls.sanitize_domain_name(untrusted_target, True)
    except ValueError:
        return 2
    source, target = untrusted_source, untrusted_target

    log = logging.getLogger('policy')
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(handler)

    return asyncio.run(handle_request(
        source,
        target,
        os.environ['QREXEC_SERVICE_ARGUMENT'],
        log))


# pylint: disable=too-many-arguments,too-many-locals
async def handle_request(
        source, intended_target, service_and_arg, log):
    log_prefix = 'qrexec: {}: {} -> {}:'.format(
        service_and_arg, source, intended_target)
    try:
        system_info = utils.get_system_info()
    except exc.QubesMgmtException as err:
        log.error('%s error getting system info: %s', log_prefix, err)
        return 1
    try:
        i = service_and_arg.index('+')
        service, argument = service_and_arg[:i], service_and_arg[i:]
    except ValueError:
        service, argument = service_and_arg, '+'

    try:
        policy = parser.FilePolicy(policy_path=POLICYPATH)

        request = parser.Request(
            service, argument, source, intended_target,
            system_info=system_info,
            ask_resolution_type=AssumeYesForAskResolution,
            allow_resolution_type=JustEvaluateAllowResolution
        resolution = policy.evaluate(request)
        await resolution.execute(caller_ident)

    except exc.PolicySyntaxError as err:
        log.error('%s error loading policy: %s', log_prefix, err)
        return 1
    except exc.AccessDenied as err:
        log.info('%s denied: %s', log_prefix, err)
        return 1
    except exc.ExecutionFailed as err:
        # Return 1, so that the source receives MSG_SERVICE_REFUSED instead of
        # hanging indefinitely.
        log.error('%s error while executing: %s', log_prefix, err)
        return 1
    except JustEvaluateResult as err:
        return err.exit_code
    return 0


if __name__ == '__main__':
    sys.exit(main())
