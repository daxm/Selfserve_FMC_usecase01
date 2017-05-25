#!/usr/bin/python3

"""
This file is the "destination" for the Flash form that the Developer will use to issue their request to open
a port in the firewall to their IP address.
"""

import fmcapi
import time
import random

__author__ = 'Dax Mickelson <dmickels@cisco.com'
__credits__ = ['Ryan Malloy <rymalloy@cisco.com>', 'Neil Patel <neipatel@cisco.com>']
__maintainer__ = 'Dax Mickelson'
__email__ = 'dmickels@cisco.com'
__repository__ = 'https://github.com/daxm/Selfserve_FMC_usecase01'
__status__ = 'Development'

#  Created or Provided by User
autodeploy = True
dev_port = random.randint(1, 65535)
dev_host_ip = '{}.{}.{}.{}'.format(random.randint(1, 223),
                                   random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))
dev_names = ['John', 'Paul', 'George', 'Ringo']
dev_name = random.choice(dev_names)

# ############################# User Created Variables to be used below functions ############################
# FMC Server Info.
username = 'apiscript'
password = 'Admin123'
serverIP = '192.168.11.5'

# Hard Coded FMC Objects Used
acp_name = 'Example_Corp'
ips_policy_name = 'Security Over Connectivity'
dst_zone_name = 'IN'
src_zone_name = 'OUT'

# Misc variables used.
dev_maxlife_seconds = 600
now_timestamp = int(time.time())
name = 'Dev-{}-{}'.format(dev_name, now_timestamp)
# name = f'Dev-{dev_name}-{now_timestamp}'  # If/when I get python3.6

protocol_port = [
    {
        'name': name,
        'port': dev_port,
        'protocol': 'TCP',
        'type': 'ProtocolPortObject',
    }
]

host_ip = [
    {
        'name': name,
        'value': dev_host_ip,
        'type': 'Host'
    }
]

acp_rule = [
    {
        'name': name,
        'acpName': acp_name,
        'action': 'ALLOW',
        'enabled': 'true',
        'logBegin': 'true',
        'logEnd': 'true',
        'ipsPolicy': ips_policy_name,
        'sourceZones': [
            {'name': src_zone_name},
        ],
        'destinationZones': [
            {'name': dst_zone_name},
        ],
        'destinationNetworks': [
            {'name': name},
        ],
        'destinationPorts': [
            {'name': name},
        ],
    },
]

# ########################################### Main Program ####################################################

with fmcapi.FMC(serverIP, username=username, password=password, autodeploy=autodeploy) as fmc1:
    # Remove timed out entries. (This will remove acprules, hostips, and protocolports.
    # Remove entries that are older than 'dev_maxlife' seconds
    expired_timestamp = int(time.time() - dev_maxlife_seconds)
    fmc1.cleanupexpiredentries(threshold_time=expired_timestamp, acp_name=acp_name)

    # Create Port and Host IP first.
    fmc1.createhostobjects(host_ip)
    fmc1.createprotocolportobjects(protocol_port)
    # Occasionally the FMC is still "sync'ing" the newly added items and this can cause the use of them in
    #  the createacprule() command to fail.  Let's wait a bit before continuing.
    time.sleep(5)

    # Create ACP Rule
    fmc1.createacprules(acp_rule)
