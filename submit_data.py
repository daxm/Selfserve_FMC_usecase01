#!/usr/bin/python3

"""
This file is the "destination" for the Flask form that the Developer will use to issue their request to open
a port in the firewall to their IP address.
"""

from fmcapi import *
import time
import random
import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())

# Its always good to set up a log file.
logging_format = '%(asctime)s - %(levelname)s:%(filename)s:%(lineno)s - %(message)s'
logging_dateformat = '%Y/%m/%d-%H:%M:%S'
# Logging level options are logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL
logging_level = logging.INFO
# logging_level = logging.DEBUG
logging_filename = 'output.log'
logging.basicConfig(format=logging_format, datefmt=logging_dateformat, filename=logging_filename, level=logging_level)


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


def cleanup_expired_dev_entries(**kwargs):
    """
    This method checks for any "expired" host, port, and acp rule objects based on a timestamp
    value in their name.
    :param kwargs:
    :return:
    """
    logging.debug("In the cleanup_expired_dev_entries() method.")

    logging.info("Checking for expired Developer Objects.")
    url_search = "/policy/accesspolicies" + "?name=" + kwargs['acp_name']
    response = kwargs['fmc'].send_to_api(method='get', url=url_search)
    acp_id = None
    if response.get('items', '') is '':
        logging.error("\tAccess Control Policy not found. Exiting.")
        exit(1)
    else:
        acp_id = response['items'][0]['id']
    # Now that we have the ACP ID.  Get all its rules and parse them to look at their names.
    url_search = "/policy/accesspolicies/" + acp_id + "/accessrules"
    response = kwargs['fmc'].send_to_api(method='get', url=url_search)
    if response.get('items', '') is '':
        logging.warning("\tNo rules found for Access Control Policy: {}.".format(kwargs['acp_name']))
    else:
        for item in response['items']:
            if 'Dev-' in item['name']:
                namesplit = item['name'].split('-')
                if int(namesplit[2]) < kwargs['threshold_time']:
                    logging.info("\tDeleting {} rule from {}.".format(item['name'], kwargs['acp_name']))
                    url = url_search + "/" + item['id']
                    kwargs['fmc'].send_to_api(method='delete', url=url)
    # Now Delete any expired Host objects.
    url_search = "/object/hosts"
    response = kwargs['fmc'].send_to_api(method='get', url=url_search)
    for item in response['items']:
        if 'Dev-' in item['name']:
            namesplit = item['name'].split('-')
            if int(namesplit[2]) < kwargs['threshold_time']:
                logging.info("\tDeleting {} host object.".format(item['name']))
                url = url_search + "/" + item['id']
                kwargs['fmc'].send_to_api(method='delete', url=url)
    # Finally Delete any expired Port objects.
    url_search = "/object/protocolportobjects"
    response = kwargs['fmc'].send_to_api(method='get', url=url_search)
    for item in response['items']:
        if 'Dev-' in item['name']:
            namesplit = item['name'].split('-')
            if int(namesplit[2]) < kwargs['threshold_time']:
                logging.info("\tDeleting {} port object.".format(item['name']))
                url = url_search + "/" + item['id']
                kwargs['fmc'].send_to_api(method='delete', url=url)


with FMC(host=serverIP, username=username, password=password, autodeploy=autodeploy) as fmc1:
    # Remove timed out entries. (This will remove acprules, hostips, and protocolports.
    # Remove entries that are older than 'dev_maxlife' seconds
    expired_timestamp = int(time.time() - dev_maxlife_seconds)
    cleanup_expired_dev_entries(threshold_time=expired_timestamp, acp_name=acp_name, fmc=fmc1)

    # Create Port and Host IP first.
    fmc1.create_host_objects(host_ip)
    fmc1.create_protocol_port_objects(protocol_port)
    # Occasionally the FMC is still "sync'ing" the newly added items and this can cause the use of them in
    #  the createacprule() command to fail.  Let's wait a bit before continuing.
    time.sleep(5)

    # Create ACP Rule
    fmc1.create_acp_rules(acp_rule)
