#!/usr/bin/python

# Copyright 2016 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import csv
import gzip
import logging
from logging.handlers import SysLogHandler
import re
import socket
from netaddr import IPNetwork, IPAddress
import requests

odl_user = 'admin'
odl_pass = 'XXXXXXX'
headers = {'content-type': "application/json",}

url_protocol = 'http://'
url_host = 'XXX.XXX.XXX.XXX'
url_port = ':8181'

# NetConf IPv4 Route Commands
# ipv4_route_payload = '{\"Cisco-IOS-XR-ip-static-cfg:vrf-prefix\": [{\"prefix\": \"%s\",\"prefix-length\": %s,\"vrf-route\": {\"vrf-next-hops\": {\"interface-name\": [{\"interface-name\": \"Null0\"}]}}}]}'

ipv4_route_payload = '''{
        "Cisco-IOS-XR-ip-static-cfg:vrf-prefix": [
            {
                "prefix": "%s",
                "prefix-length": %s,
                "vrf-route": {
                    "vrf-next-hops": {
                        "interface-name": [
                            {
                                "interface-name": "Null0",
                                "tag": 666
                            }
                        ]
                    }
                }
            }
        ]
}'''

# Setup Syslog Logging
logger = logging.getLogger('splunk_odl_action')
logger.setLevel(logging.DEBUG)
syslog = logging.handlers.SysLogHandler(facility=SysLogHandler.LOG_LOCAL5) 
formatter = logging.Formatter('%(name)s: log_level=%(levelname)s, %(message)s')
syslog.setFormatter(formatter)
logger.addHandler(syslog)

whitelist = [
    '192.168.0.0/16',
    '10.0.0.0/8'
    ]

def inWhitelist(ip):
    for network in whitelist:
        if IPAddress(ip) in IPNetwork(network):
            return True
    return False

def nullRoute(event, action, src_ip):
    log_mesg = 'event=%s, action=%s, src_ip=%s'
    if inWhitelist(src_ip):
        action='whitelisted'
        logger.debug (log_mesg % (event, action, src_ip))
    log_mesg = 'event=%s, action=%s, src_ip=%s status_code=%s'
    if action == 'block':
        url_path = '/restconf/config/opendaylight-inventory:nodes/node/asr9k/yang-ext:mount/Cisco-IOS-XR-ip-static-cfg:router-static/default-vrf/address-family/vrfipv4/vrf-unicast/vrf-prefixes'
        url = url_protocol + url_host + url_port + url_path 
        payload = ipv4_route_payload % (src_ip, '32')
        response = requests.request("POST", url, data=payload, headers=headers, auth=(odl_user, odl_pass))
        logger.info (log_mesg % (event, action, src_ip, response.status_code))
    elif action == 'unblock':
       url_path = '/restconf/config/opendaylight-inventory:nodes/node/asr9k/yang-ext:mount/Cisco-IOS-XR-ip-static-cfg:router-static/default-vrf/address-family/vrfipv4/vrf-unicast/vrf-prefixes/vrf-prefix/'
       url = url_protocol + url_host + url_port + url_path + src_ip + '/32' 
       response = requests.request("DELETE", url, headers=headers, auth=(odl_user, odl_pass))
       logger.info (log_mesg % (event, action, src_ip, response.status_code))

if __name__ == "__main__":
    try: 
        alertEventsFile = os.environ['SPLUNK_ARG_8']
    except:
        logger.exception ('action=error, reason="Error reading SPLUNK_ARG_8 environmental variable"')
        raise

    if os.path.isfile(alertEventsFile) and os.access(alertEventsFile, os.R_OK):
#        logger.debug ("results_file=" + alertEventsFile)
        try:
            eventContents = csv.DictReader(gzip.open(alertEventsFile, 'rb'))
        except:
            logger.exception ('action=error, reason="Could not read event file"')
            raise
    else:
        logger.error ('action=error, reason="' + alertEventsFile + ' does not exist"')
        sys.exit(1)

    targetlist = []
    uniquetargetlist = []
    mesg_value = {}
    sourceType = 'Unknown'
    event = 'unknown'
    reason = 'unknown'
    action = 'unknown'
    src_ip = 'unknown'
    for row in eventContents:
        if 'params' in row.keys():
            params_string = row['params']
            pairs = params_string.split(',', 1)
            params = dict(pair.split('=',1) for pair in pairs)
        else:
            logger.error ('action=error,reason="Could not find params"')
            sys.exit(1)

        if 'event' in params.keys():
            event = params['event']
        else:
            logger.error ('action=error,reason="Could not find event in params"')
            sys.exit(1)

        action = params['action']

        if event == 'block_timeout':
           if 'src_ip' in row.keys():
               src_ip = row["src_ip"]
               if row["src_ip"] not in targetlist:
                   targetlist.append(row["src_ip"])
           else:
               logger.error ('action=error,reason="Could not find src_ip in CSV"')
               sys.exit(1)
           nullRoute (event, action, src_ip)
        elif event.startswith('asa-'):
            if 'src_ip' in row.keys():
                src_ip = row["src_ip"]
                if row["src_ip"] not in targetlist:
                    targetlist.append(row["src_ip"])
            else:
                logger.error ('action=error,reason="Could not find src_ip in CSV"')
                sys.exit(1)
            nullRoute (event, action, src_ip)
        elif event.startswith('ids-'):
                if '_raw' in row.keys():
                    match = re.search (r' src_ip=([^=]+) ', row['_raw'])
                else:
                    logger.error ('action=error,reason="Could not parse raw message"')
                    sys.exit(1)
                if match:
                    src_ip = match.group(1) 
                else:
                    logger.error ('action=error,reason="Could not find src_ip in ids event"')
                    sys.exit(1)
                nullRoute (event, action, src_ip)
        else:
            logger.error ('action=error,reason="Unknown event ' + event + '"')
            sys.exit(1)
sys.exit(0)
