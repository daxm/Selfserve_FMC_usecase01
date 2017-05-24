
import fmcapi
import time
import random

#  Created or Provided by User
dev_port = random.randint(1, 65535)
dev_host_ip = '{}.{}.{}.{}'.format(random.randint(1, 223),
                                   random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
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

with fmcapi.FMC(serverIP, username=username, password=password) as fmc1:
    # Remove timed out entries. (This will remove acprules, hostips, and protocolports.
    # Remove entries that are older than 'dev_maxlife' seconds
    expired_timestamp = int(time.time() - dev_maxlife_seconds)
    fmc1.cleanupexpiredentries(threshold_time=expired_timestamp, acp_name=acp_name)

    # Create Port and Host IP first.
    fmc1.createhostobjects(host_ip)
    fmc1.createprotocolportobjects(protocol_port)
    # Create ACP Rule
    fmc1.createacprules(acp_rule)
