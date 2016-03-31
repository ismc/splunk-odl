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
import requests

odl_user = 'admin'
odl_pass = 'XXXXXXXXXXXX'
headers = {'content-type': "application/json",}

url_protocol = 'http://'
url_host = 'XXX.XXX.XXX.XXX'
url_port = ':8181'

# OpenFLow IPv4 Flow Commands
local_of_port = '54'
remote_of_port= '52'
flow_id_template = '%s:%s-%s:%s'
ipv4_flow_url = 'http://XXX.XXX.XXX.XXX:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:431397570163232/table/0/flow/'
ipv4_flow_payload = '''{
    "flow": [
        {
            "table_id": 0,
            "id": "%s",
            "priority": 200,
            "hard-timeout": 0,
            "idle-timeout": 0,
            "match": {
                "in-port": "openflow:431397570163232:%s",
                "ethernet-match": {
                    "ethernet-type": {
                        "type": 2048
                    }
                },
                  "ip-match": {
                        "ip-protocol": "6"
                },
                "ipv4-source": "%s/32",
                "tcp-source-port": %s,
                "ipv4-destination": "%s/32",
                "tcp-destination-port": %s
            },
            "instructions": {
                "instruction": [
                    {
                        "order": 0,
                        "apply-actions": {
                            "action": [
                                {
                                    "order": 0,
                                    "output-action": {
                                        "output-node-connector": %s
                                    }
                                }
                            ]
                        }
                    }
                ]
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

def validateIP(addr):
    try:
        socket.inet_aton(addr)
        return addr 
    except socket.error:
        try:
            return socket.gethostbyname(addr)
        except:
            return 'unknown'

if __name__ == "__main__":
	# Get the file containing the event data for the alert
    try: 
        alertEventsFile = os.environ['SPLUNK_ARG_8']
    except:
        logger.exception ('action=error, reason="Error reading SPLUNK_ARG_8 environmental variable!"')
        raise
	
	# Read the event data
    if os.path.isfile(alertEventsFile) and os.access(alertEventsFile, os.R_OK):
#        logger.debug ("results_file=" + alertEventsFile)
        try:
            eventContents = csv.DictReader(gzip.open(alertEventsFile, 'rb'))
        except:
            logger.exception ('action=error, reason="Could not read event file!"')
            raise
    else:
        logger.error ('action=error, reason="' + alertEventsFile + ' does not exist!"')
        sys.exit(1)

    event = 'unknown'
    reason = 'unknown'
    action = 'unknown'
    
    # We should get one row for every flow involved in the Globus transfer
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

        if event == 'flow':
            if '_raw' in row.keys():
                (pre_mesg, raw_mesg) = row['_raw'].split(':', 1)
                raw_pairs = raw_mesg.split(',')
                raw_record = dict(pair.split('=',1) for pair in raw_pairs)
            else:
                logger.error ('action=error,reason="Could not parse raw message!"')
                sys.exit(1)
            # For the Globus Flows, we get 'action' from the event message so that we can do both start and stop with one search 
            action = raw_record['action'] 
            event = row['event']
            (local_ip_raw, local_port) = raw_record['local_contact'].split(':')
            local_ip = validateIP(local_ip_raw)
            (remote_ip_raw, remote_port) = raw_record['remote_contact'].split(':')
            remote_ip = validateIP(remote_ip_raw)
            log_mesg = 'event=%s, action=%s, transport=%s, local_ip=%s, local_port=%s, remote_ip=%s, remote_port=%s'
            logger.debug (log_mesg % (event, action, raw_record['transport'], local_ip, local_port, remote_ip, remote_port))
            log_mesg = 'action=%s, flow=%s, status_code=%s'
            if (local_ip == 'unknown' or remote_ip == 'unknown'):
                logger.error ('action=error,reason="Unknown IP address!"')
                sys.exit(1)
            if action == 'start':
                flow_id = flow_id_template % (local_ip, local_port, remote_ip, remote_port)
                payload = ipv4_flow_payload % (flow_id, local_of_port, local_ip, local_port, remote_ip, remote_port, remote_of_port)
                url =  ipv4_flow_url + flow_id
                response = requests.request("PUT", url, data=payload, headers=headers, auth=(odl_user, odl_pass))
                logger.info (log_mesg % (action, flow_id, str(response.status_code)))

                flow_id = flow_id_template % (remote_ip, remote_port, local_ip, local_port)
                payload = ipv4_flow_payload % (flow_id, remote_of_port, remote_ip, remote_port, local_ip, local_port, local_of_port)
                url =  ipv4_flow_url + flow_id
                response = requests.request("PUT", url, data=payload, headers=headers, auth=(odl_user, odl_pass))
                logger.info (log_mesg % (action, flow_id, str(response.status_code)))
            elif action == 'stop':
                flow_id = flow_id_template % (local_ip, local_port, remote_ip, remote_port)
                url =  ipv4_flow_url + flow_id
                response = requests.request("DELETE", url, headers=headers, auth=(odl_user, odl_pass))
                logger.info (log_mesg % (action, flow_id, str(response.status_code)))

                flow_id = flow_id_template % (remote_ip, remote_port, local_ip, local_port)
                url =  ipv4_flow_url + flow_id
                response = requests.request("DELETE", url, headers=headers, auth=(odl_user, odl_pass))
                logger.info (log_mesg % (action, flow_id, str(response.status_code)))
        else:
            logger.error ('action=error,reason="Unknown event ' + event + '"')
            sys.exit(1)
sys.exit(0)
