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
autodeploy = False
dev_port = random.randint(1, 65535)
protocol_list = ['UDP', 'TCP']
dev_protocol = random.choice(protocol_list)
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

    # Get all rules for this ACP.

    all_acp_rules = ACPRule(fmc=fmc1, acp_name=acp_name)
    all_rules = all_acp_rules.get()
    if all_rules.get('items', '') is '':
        logging.warning("\tNo rules found for Access Control Policy: {}.".format(kwargs['acp_name']))
    else:
        for item in all_rules['items']:
            if 'Dev-' in item['name']:
                namesplit = item['name'].split('-')
                if int(namesplit[2]) < kwargs['threshold_time']:
                    logging.info("\tDeleting {} rule from {}.".format(item['name'], kwargs['acp_name']))
                    tmp_rule = None
                    tmp_rule = ACPRule(fmc=fmc1, acp_name=acp_name)
                    tmp_rule.get(name=item['name'])
                    tmp_rule.delete()
    # Now Delete any expired Host objects.
    all_ips = IPAddresses(fmc=fmc1)
    all_hosts = all_ips.get()
    for item in all_hosts['items']:
        if 'Dev-' in item['name']:
            namesplit = item['name'].split('-')
            if int(namesplit[2]) < kwargs['threshold_time']:
                logging.info("\tDeleting {} host object.".format(item['name']))
                tmp_rule = None
                tmp_rule = IPHost(fmc=fmc1)
                tmp_rule.get(name=item['name'])
                tmp_rule.delete()
    # Finally Delete any expired Port objects.
    all_ports = ProtocolPort(fmc=fmc1)
    response = all_ports.get()
    for item in response['items']:
        if 'Dev-' in item['name']:
            namesplit = item['name'].split('-')
            if int(namesplit[2]) < kwargs['threshold_time']:
                logging.info("\tDeleting {} port object.".format(item['name']))
                tmp_rule = None
                tmp_rule = ProtocolPort(fmc=fmc1)
                tmp_rule.get(name=item['name'])
                tmp_rule.delete()


with FMC(host=serverIP, username=username, password=password, autodeploy=autodeploy) as fmc1:
    # Remove timed out entries. (This will remove acprules, hostips, and protocolports.
    # Remove entries that are older than 'dev_maxlife' seconds
    expired_timestamp = int(time.time() - dev_maxlife_seconds)
    cleanup_expired_dev_entries(threshold_time=expired_timestamp, acp_name=acp_name, fmc=fmc1)

    # Create Port and Host IP first.
    pport = ProtocolPort(fmc=fmc1, name=name, port=dev_port, protocol=dev_protocol)
    pport.post()
    host_ip = IPHost(fmc=fmc1, name=name, value=dev_host_ip)
    host_ip.post()

    # Create ACP Rule
    acp_rule = ACPRule(fmc=fmc1, name=name, acp_name=acp_name, action='ALLOW', enabled=True, logBegin=True, logEnd=True)
    acp_rule.intrusion_policy(action='set', name='Security Over Connectivity')
    acp_rule.source_zone(action='add', name=src_zone_name)
    acp_rule.destination_zone(action='add', name=dst_zone_name)
    acp_rule.destination_network(action='add', name=name)
    acp_rule.destination_port(action='add', name=name)
    acp_rule.post()
