#!/usr/bin/env python3
# written by mohlcyber 17/03/2021 v0.1
# This script to pull Threat Detection from the Active Response Workspace

import logging
import requests
import json
import sys
import getpass

from bs4 import BeautifulSoup as BS
from argparse import ArgumentParser, RawTextHelpFormatter

requests.packages.urllib3.disable_warnings()


class EPO():
    def __init__(self):
        self.verify = False
        self.epo = args.epo_ip
        self.port = args.epo_port
        self.user = args.epo_user
        self.pw = args.epo_pw
        self.hours = args.hours

        self.session = requests.Session()

        self.logger = logging.getLogger('logs')
        self.logger.setLevel(args.loglevel)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.session.verify = False
        self.setup()

    def setup(self):
        res = self.session.get('https://{0}:{1}/core/orionSplashScreen.do'.format(self.epo, self.port))
        if not res.ok:
            self.logger.error('Error in setup(). {0}-{1}'.format(str(res.status_code), res.text))
            sys.exit()

    def auth(self):
        data = {
            "j_username": self.user,
            "j_password": self.pw
        }

        res = self.session.post('https://{0}:{1}/core/j_security_check'.format(self.epo, self.port),
                                data=data)

        if res.ok:
            self.logger.info('Successfully authenticated.')
            return res.text
        else:
            self.logger.error('Error in auth(). {0}-{1}'.format(str(res.status_code), res.text))
            sys.exit()

    def get_events(self, token):
        params = [
            {
                'field': 'processAccumSeverity',
                'values': ['s0', 's1', 's2', 's3', 's4', 's5']
            },
            {
                'field': 'searchText','values':['']
            },
            {
                'field': 'flagged', 'values': [False]
            },
            {
                'field': 'isRoot',
                'values': ['true']
            }
        ]

        res = self.session.get('https://{0}:{1}/rest/edr/v1/traces/list?filter={2}&limit=100&since={3}'
                               '&orion.user.security.token={4}'
                               .format(self.epo, self.port, json.dumps(params), self.hours, token))

        if res.ok:
            return res.text
        else:
            self.logger.error('Error in get_ws_events(). {0}-{1}'.format(str(res.status_code), res.text))
            sys.exit()

    def get_rep(self, md5, sha1, sha256, token):
        params = {
            'hashes': [[
                {'value': md5, 'type': 'md5'},
                {'value': sha1,'type':'sha1'},
                {'value': sha256,'type':'sha256'},
            ]]
        }

        res = self.session.get('https://{0}:{1}/rest/edr/v1/pe-reputations?query={2}&orion.user.security.token={3}'
                               .format(self.epo, self.port, json.dumps(params), token))

        if res.ok:
            return res.text
        else:
            self.logger.error('Error in get_rep(). {0}-{1}'.format(str(res.status_code), res.text))
            sys.exit()

    def get_hosts(self, sha256, token):
        res = self.session.get('https://{0}:{1}/rest/edr/v1/traces/SHA256-{2}/hosts?limit=1000&sort=host'
                               '&sortDirection=asc&since={3}&orion.user.security.token={4}'
                               .format(self.epo, self.port, sha256, self.hours, token))

        if res.ok:
            return res.text
        else:
            self.logger.error('Error in get_rep(). {0}-{1}'.format(str(res.status_code), res.text))
            sys.exit()

    def get_traces(self, md5, sha1, sha256, maguid, token):
        res = self.session.get('https://{0}:{1}/rest/edr/v1/traces/events?md5={2}&sha1={3}&sha256={4}&maGuid={5}'
                               '&timeframe={6}&limit=1000&orion.user.security.token={7}'
                               .format(self.epo, self.port, md5, sha1, sha256, maguid, self.hours, token))

        if res.ok:
            return res.text
        else:
            self.logger.error('Error in get_rep(). {0}-{1}'.format(str(res.status_code), res.text))
            sys.exit()


    def main(self):
        login = self.auth()
        page = BS(login, features="html.parser")
        token = page.find('input', {'id': 'orion.user.security.token'}).get('value')

        events = self.get_events(token)
        for event in json.loads(events)['threats']:
            md5 = event['md5Hash']
            sha1 = event['sha1Hash']
            sha256 = event['sha256Hash']

            reputations = self.get_rep(md5, sha1, sha256, token)
            event['reputations'] = json.loads(reputations)

            systems = []
            hosts = self.get_hosts(sha256, token)
            for host in json.loads(hosts)['items']:
                maguid = host['guid']
                traces = self.get_traces(md5, sha1, sha256, maguid, token)
                host['traces'] = json.loads(traces)
                systems.append(host)

            event['hosts'] = systems

            self.logger.info(json.dumps(event))
            sys.exit()


if __name__ == '__main__':
    usage = """python3 mar_workspace_api.py -h"""
    title = 'McAfee MAR Workspace API'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--epo_ip', '-I',
                        required=True, type=str,
                        help='McAfee EPO IP/Hostname')

    parser.add_argument('--epo_port', '-P',
                        required=True, type=int,
                        help='McAfee EPO Port')

    parser.add_argument('--epo_user', '-U',
                        required=True, type=str,
                        help='McAfee NSM Username')

    parser.add_argument('--epo_pw', '-PW',
                        required=False, type=str,
                        help='McAfee NSM Password')

    parser.add_argument('--hours', '-H', required=True,
                        type=int, help='Time to go back in hours')

    parser.add_argument('--loglevel', '-L', type=str,
                        required=False, default='INFO',
                        help='Loglevel', choices=['INFO', 'DEBUG'])

    args = parser.parse_args()
    if not args.epo_pw:
        args.epo_pw = getpass.getpass(prompt='McAfee EPO Password:')

    EPO().main()
