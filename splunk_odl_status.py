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
from socket import inet_aton
import requests
import struct

odl_user = 'admin'
odl_pass = 'XXXXXXX'
headers = {'content-type': "application/json",}

url_protocol = 'http://'
url_host = 'XXX.XXX.XXX.XXX'
url_port = ':8181'

# Setup Syslog Logging
logger = logging.getLogger('splunk_odl_action')
logger.setLevel(logging.DEBUG)
syslog = logging.handlers.SysLogHandler(facility=SysLogHandler.LOG_LOCAL5) 
formatter = logging.Formatter('%(name)s: log_level=%(levelname)s, %(message)s')
syslog.setFormatter(formatter)
logger.addHandler(syslog)

if __name__ == "__main__":
    entry = ''
    i = 0
    addrs = []
    log_mesg = 'GET status_code=%s'
    url_path = '/restconf/config/opendaylight-inventory:nodes/node/asr9k/yang-ext:mount/Cisco-IOS-XR-ip-static-cfg:router-static/default-vrf/address-family/vrfipv4/vrf-unicast/vrf-prefixes'
    url = url_protocol + url_host + url_port + url_path 
    response = requests.request("GET", url, headers=headers, auth=(odl_user, odl_pass))
    if response.status_code != 200:
        logger.info (log_mesg % response.status_code)
        sys.exit(1)

    data = response.json()

    for row in data['vrf-prefixes']['vrf-prefix']:
        addrs.append(row['prefix'])

    addrs = sorted(addrs, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0], reverse=True)
    
    for addr in addrs:
        prefix = "prefix=%s" % addr
        print prefix
        
sys.exit(0)
