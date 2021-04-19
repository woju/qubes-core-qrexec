#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2017 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
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
import logging
import logging.handlers
import pathlib
import sys
import asyncio

from .. import DEFAULT_POLICY, POLICYPATH
from .. import exc
from .. import utils
from ..policy import parser
from ..policy.utils import PolicyCache
from ..server import call_socket_service


def create_default_policy(service_name):
    with open(str(POLICYPATH / service_name), 'w') as policy:
        policy.write(DEFAULT_POLICY)


class JustEvaluateResult(Exception):
    def __init__(self, exit_code):
        super().__init__()
        self.exit_code = exit_code


class JustEvaluateAllowResolution(parser.AllowResolution):
    async def execute(self, caller_ident):
        raise JustEvaluateResult(0)


class JustEvaluateAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        raise JustEvaluateResult(1)


class AssumeYesForAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        return await self.handle_user_response(
            True, self.request.target).execute(caller_ident)


class AgentAskResolution(parser.AskResolution):
    async def execute(self, caller_ident):
        domains = self.request.system_info['domains']
        guivm = domains[self.request.source]['guivm']
        if not guivm:
            log = logging.getLogger('policy')
            log.error('%s not allowed from %s: the resolution was "ask", '
                      'but source domain has no GuiVM',
                      self.request.service, self.request.source)
            self.handle_user_response(False, None)
            assert False, 'handle_user_response should throw'

        # prepare icons
        icons = {name: domains[name]['icon'] for name in domains.keys()}
        for dispvm_base in domains:
            if not (domains[dispvm_base]['template_for_dispvms']):
                continue
            dispvm_api_name = '@dispvm:' + dispvm_base
            icons[dispvm_api_name] = domains[dispvm_base]['icon']
            icons[dispvm_api_name] = \
                icons[dispvm_api_name].replace('app', 'disp')

        params = {
            'source': self.request.source,
            'service': self.request.service,
            'argument': self.request.argument,
            'targets': self.targets_for_ask,
            'default_target': self.default_target or '',
            'icons': icons,
        }

        service = 'policy.Ask'
        source_domain = 'dom0'
        ask_response = await call_socket_service(
            guivm, service, source_domain, params)

        if ask_response == 'deny':
            self.handle_user_response(False, None)
            assert False, 'handle_user_response should throw'

        if ask_response.startswith('allow:'):
            target = ask_response[len('allow:'):]
            resolution = self.handle_user_response(True, target)
            return await resolution.execute(caller_ident)

        log = logging.getLogger('policy')
        log.error('invalid ask response for %s: %s',
                  self.request.service, ask_response)
        self.handle_invalid_response()
        assert False, 'handle_invalid_response should throw'


class NotifyAllowedResolution(parser.AllowResolution):
    async def execute(self, caller_ident):
        try:
            guivm = \
            self.request.system_info['domains'][self.request.source]['guivm']
        except KeyError:
            guivm = None

        if self.notify:
            if guivm:
                await notify(guivm, {
                    'resolution': 'allow',
                    'service': self.request.service,
                    'argument': self.request.argument,
                    'source': self.request.source,
                    'target': self.target,
                })
        try:
            await super().execute(caller_ident)
        except exc.ExecutionFailed:
            if guivm:
                await notify(guivm, {
                    'resolution': 'fail',
                    'service': self.request.service,
                    'argument': self.request.argument,
                    'source': self.request.source,
                    'target': self.target,
                })
            # Handle in handle_request()
            raise


async def notify(guivm, params):
    service = 'policy.Notify'
    source_domain = 'dom0'
    try:
        await call_socket_service(guivm, service, source_domain, params)
    # pylint: disable=broad-except
    except Exception:
        # qrexec-policy-agent might be dead or malfunctioning, log exception
        # but do not fail the whole operation
        log = logging.getLogger('policy')
        log.exception('error calling qrexec-policy-agent in %s', guivm)


class LogAllowedResolution(NotifyAllowedResolution):
    async def execute(self, caller_ident):
        log_prefix = 'qrexec: {request.service}{request.argument}: ' \
                     '{request.source} -> {request.target}:'.format(
                      request=self.request)

        log = logging.getLogger('policy')
        log.info('%s allowed to %s', log_prefix, self.target)

        await super().execute(caller_ident)


def prepare_resolution_types(*, just_evaluate, assume_yes_for_ask,
                             allow_resolution_type):
    ret = {
        'ask_resolution_type': AgentAskResolution,
        'allow_resolution_type': allow_resolution_type}
    if just_evaluate:
        ret['ask_resolution_type'] = JustEvaluateAskResolution
        ret['allow_resolution_type'] = JustEvaluateAllowResolution
    if assume_yes_for_ask:
        ret['ask_resolution_type'] = AssumeYesForAskResolution
    return ret


argparser = argparse.ArgumentParser(description='Evaluate qrexec policy')

argparser.add_argument('--assume-yes-for-ask', action='store_true',
    dest='assume_yes_for_ask', default=False,
    help='Allow run of service without confirmation if policy say \'ask\'')
argparser.add_argument('--just-evaluate', action='store_true',
    dest='just_evaluate', default=False,
    help='Do not run the service, only evaluate policy; '
         'retcode=0 means \'allow\'')
argparser.add_argument('--path',
    type=pathlib.Path, default=POLICYPATH,
    help='Use alternative policy path')

argparser.add_argument('domain_id', metavar='src-domain-id',
    help='Source domain ID (Xen ID or similar, not Qubes ID)')
argparser.add_argument('source', metavar='SOURCE',
    help='Source domain name')
argparser.add_argument('intended_target', metavar='TARGET',
    help='Target domain name')
argparser.add_argument('service_and_arg', metavar='SERVICE+ARGUMENT',
    help='Service name')
argparser.add_argument('process_ident', metavar='process-ident',
    help='Qrexec process identifier - for connecting data channel')


def main(args=None):
    args = argparser.parse_args(args)

    log = logging.getLogger('policy')
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(handler)

    policy_cache = PolicyCache(args.path)

    return asyncio.run(handle_request(
        args.domain_id,
        args.source,
        args.intended_target,
        args.service_and_arg,
        args.process_ident,
        log,
        just_evaluate=args.just_evaluate,
        assume_yes_for_ask=args.assume_yes_for_ask,
        policy_cache=policy_cache))


# pylint: disable=too-many-arguments,too-many-locals
async def handle_request(
        domain_id, source, intended_target, service_and_arg, process_ident,
        log, just_evaluate=False, assume_yes_for_ask=False,
        allow_resolution_type=None, policy_cache=None):
    # Add source domain information, required by qrexec-client for establishing
    # connection
    caller_ident = process_ident + "," + source + "," + domain_id
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
        if policy_cache:
            policy = policy_cache.get_policy()
        else:
            policy = parser.FilePolicy(policy_path=POLICYPATH)

        if allow_resolution_type is None:
            allow_resolution_class = LogAllowedResolution
        else:
            allow_resolution_class = allow_resolution_type

        request = parser.Request(
            service, argument, source, intended_target,
            system_info=system_info,
            **prepare_resolution_types(
                just_evaluate=just_evaluate,
                assume_yes_for_ask=assume_yes_for_ask,
                allow_resolution_type=allow_resolution_class))
        resolution = policy.evaluate(request)
        await resolution.execute(caller_ident)

    except exc.PolicySyntaxError as err:
        log.error('%s error loading policy: %s', log_prefix, err)
        return 1
    except exc.AccessDenied as err:
        log.info('%s denied: %s', log_prefix, err)

        if err.notify and not just_evaluate:
            guivm = \
                system_info['domains'][source]['guivm']
            if guivm:
                await notify(guivm, {
                    'resolution': 'deny',
                    'service': service,
                    'argument': argument,
                    'source': source,
                    'target': intended_target,
                })

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
