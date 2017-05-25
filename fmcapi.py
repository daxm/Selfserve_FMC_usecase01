import logging
import datetime
import json
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable annoying HTTP warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

"""
Firepower Management Center API script class for managing Firepower Threat Defense
 and legacy Firepower devices through a Firepower Management Center.
 
There exists a "Quick Start Guide" for the FMC API too.  Just Google for it as it gets updated with each
 release of code.
 
"""

# Creating a custom log level to enable "logging" of the documentation.  Use via command 'logging.log(DOC,<string>)'.
# This custom logging level is "in between DEBUG and INFO".  So, you can enable detailed documentation about each
# method and class in this module without adding the DEBUG output as well.
DOC = 15
logging.addLevelName(DOC, 'DOC')

# Its always good to set up a log file.
logging_format = '%(asctime)s - %(levelname)s - %(message)s'
logging_dateformat = '%Y/%m/%d-%H:%M:%S'
logging_level = logging.INFO  # Options are DEBUG, DOC, INFO, WARNING, ERROR, CRITICAL
# logging_level = DOC
logging_filename = 'output.log'
logging.basicConfig(format=logging_format, datefmt=logging_dateformat, filename=logging_filename, level=logging_level)
logging.log(DOC, """Note: Documentation logging is enabled.
This will result in a lot of logging but hopefully the output will be educational on what is going on in the code as
it is running.
 """)


logging.log(DOC, """The 'requests' package is very chatty on the INFO logging level.
Change its logging threshold sent to logger to something greater than INFO (i.e. not INFO or DEBUG) will cause it to
not log its INFO and DEBUG messages to the default logger.  This reduces the size of our log files.
""")
logging.getLogger("requests").setLevel(logging.WARNING)

logging.log(DOC, """FMC is a class object in python.  Think of it as a "template" to be used to create instances of.
In our code we create an instance called 'fmc1' of the FMC class and then access the FMC class' methods via 'fmc1'.
""")


class FMC(object):
    logging.log(DOC, """The FMC class has a series of methods, "def", that are used to interact with the Cisco FMC
via its API.    
""")
    logging.log(DOC, """Variables that are assigned in a class (but not in one of a class' methods) are called
class variables.  The idea behind these are that these variables are the same for all instances created of this class.
""")
    API_PLATFORM_VERSION = '/api/fmc_platform/v1/'
    API_CONFIG_VERSION = '/api/fmc_config/v1/'
    VERIFY_CERT = False
    TOKEN_LIFETIME = 60 * 30
    
    def __init__(self, host, username='admin', password='Admin123', autodeploy=True):
        logging.log(DOC, """In the __init__() (pronounced "dunder init") method. 
This method is ran each time an instance of the class is created.
Typically, you configure your instance variables here.
""")
        self.host = host
        self.username = username
        self.password = password
        self.autodeploy = autodeploy
        self.token_expiry = datetime.datetime.now()
        self.refreshtoken = ''
        self.token_refreshes = 0
        self.token = ''
        self.uuid = ''
        self.base_url = ''

    def __enter__(self):
        logging.log(DOC, """In the __enter__() (pronounced "dunder enter") method.
This method is similar to the __init__ method in that it is ran at the moment 
an instance of this class is created.  The subtle difference is that it has an assocated method, __exit__.  The
 __enter__ method is used to start/open things for this class instance that will need to be ended/closed when the 
associated class instance is destroyed.
An example of when to use __enter__ is if you need to perform some sort of file locking to ensure that multiple 
instances of a program are running at the same time.
In our case we are using the __enter_ method to establish a connection to the FMC via the connect() method.
""")
        self.connect()
        return self
        
    def __exit__(self, *args):
        logging.log(DOC, """In the __exit__() (pronounced "dunder exit") method.
This method is executed when an instance of the class is destroyed.
Typically this is where you would put things that end/close whatever you might have set up in the __enter__ method.
In our program that means that we are done with the 'fmc1' instance.  However, prior to exiting the instance we should
submit our changes to the FMC.  We have a variable called "autodeploy" which if set to True will run the method 
deploychanges() to push our configuration changes to the FMC to any devices that might need updated due to these 
changes.
""")
        if self.autodeploy:
            self.deploychanges()
        else:
            logging.info("Auto deploy changes set to False.  "
                         "Use the Deploy button in FMC to push changes to FTDs.\n\n")

# FMC Connection Maintenance

    # FMC Connection and Token Maintenance

    def reset_token_expiry(self):
        logging.log(DOC, """In the reset_token_expiry() method.
This method sets the instance variable self.token_expiry to the time in which our token with the FMC will expire.
We will use this variable to see whether we need to refresh our token with the FMC.
""")
        self.token_expiry = datetime.datetime.now() + datetime.timedelta(seconds=self.TOKEN_LIFETIME)

    def refresh_token(self):
        logging.log(DOC, """In the refresh_token() method.
This method refreshes our token with the FMC if/when our token is expired.  Given that our program's connection to 
the FMC is short lived it is very doubtful we will ever enter this method.
""")
        headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.token,
                   'X-auth-refresh-token': self.refreshtoken}
        url = "https://" + self.host + self.API_PLATFORM_VERSION + "auth/refreshtoken"
        logging.info("Refreshing token from {}.".format(url))
        response = requests.post(url, headers=headers, verify=self.VERIFY_CERT)
        self.token_refreshes += 1
        self.reset_token_expiry()
        self.token = response.headers.get('X-auth-access-token')
        self.refreshtoken = response.headers.get('X-auth-refresh-token')
        headers['X-auth-access-token'] = self.token
        
    def connect(self):
        logging.log(DOC, """In the connect() method.
This method is used to set up our connection with the FMC.  Essentially this method issues a POST request to the FMC 
providing our credentials (and possibly SSL cert, not implemented yet).  The FMC will generate a token value and 
return that value along with the "domain UUID" (which is the GLOBAL UUID by default).  We use these returned values 
to set our associated instance variables.
""")
        headers = {'Content-Type': 'application/json'}
        url = "https://" + self.host + self.API_PLATFORM_VERSION + "auth/generatetoken"
        logging.info("Requesting token from {}.".format(url))
        response = requests.post(url, headers=headers,
                                 auth=requests.auth.HTTPBasicAuth(self.username, self.password),
                                 verify=self.VERIFY_CERT)
        self.token = response.headers.get('X-auth-access-token')
        self.refreshtoken = response.headers.get('X-auth-refresh-token')
        self.uuid = response.headers.get('DOMAIN_UUID')
        if self.token is None or self.uuid is None:
            logging.error("No Token or DOMAIN_UUID found, terminating....")
            exit(1)

        self.base_url = "https://" + self.host + self.API_CONFIG_VERSION + "domain/" + self.uuid
        self.reset_token_expiry()
        self.token_refreshes = 0
        logging.info("\tToken creation a success --> {} expires at {}".format(self.token, self.token_expiry))

    def checktoken(self):
        logging.log(DOC, """In the checktoken() method.
This method checks the age of our token with the self.token_expiry variable value to ensure our token has expired.
If our token has expired it will use the connect() method to generate a new one.
""")
        if datetime.datetime.now() > self.token_expiry:
            logging.info("Token Expired.  Generating new token.")
            self.connect()

# API Method Calls

    # FMC to FTD Interactions

    def send_to_api(self, method='', url='', json_data={}):
        logging.log(DOC, """In the send_to_api() method.
This method is used to send GET/POST/PUT/DELETE requests to the FMC.  First we check the validity of our token, 
then using the values passed into this method we connect to the FMC using the requests library.  The FMC does 
rate limit the number of API connections to 120 per minute.  So, we use the status_code to continue trying until 
we don't exceed that limit.  If we don't get a status_code error (300 or higher means something is wrong) we return 
the response to whatever called this method.
""")
        self.checktoken()
        # POST json_data with the REST CALL
        try:
            headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.token}
            url = self.base_url + url
            status_code = 429
            while status_code == 429:
                if method == 'get':
                    response = requests.get(url, headers=headers, verify=self.VERIFY_CERT)
                elif method == 'post':
                    response = requests.post(url, json=json_data, headers=headers, verify=self.VERIFY_CERT)
                elif method == 'put':
                    response = requests.put(url, json=json_data, headers=headers, verify=self.VERIFY_CERT)
                elif method == 'delete':
                    response = requests.delete(url, headers=headers, verify=self.VERIFY_CERT)
                else:
                    logging.error("No request method given.  Returning nothing.")
                    return
                status_code = response.status_code
                if status_code == 429:
                    logging.warning("Too many connections to the FMC.  Waiting 30 seconds and trying again.")
                    time.sleep(30)
            json_response = json.loads(response.text)
            if status_code > 301 or 'error' in json_response:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.error("Error in POST operation --> {}".format(str(err)))
            logging.error("json_response -->\t{}".format(json_response))
        if response:
            response.close()
        return json_response

    def getdeployabledevices(self):
        logging.log(DOC, """In the getdeployabledevices() method.
This method will tabulate which devices managed by the FMC are needing updated due to changes in the FMC.
Once it has a complete list it will return that list to whatever called this method.
We need to wait a little bit (I found 15 seconds to work) so that any changes made in the FMC can be tabulated against
the FMC's managed devices to update what needs deployments (or not).
""")
        waittime = 15
        logging.info("Waiting {} seconds to allow the FMC to update the list of deployable devices.".format(waittime))
        time.sleep(waittime)
        logging.info("Getting a list of deployable devices.")
        url = "/deployment/deployabledevices?expanded=true"
        response = self.send_to_api(method='get', url=url)
        # Now to parse the response list to get the UUIDs of each device.
        if 'items' not in response:
            return
        uuids = []
        for item in response['items']:
            if not item['canBeDeployed']:
                pass
            else:
                uuids.append(item['device']['id'])
        return uuids

    def deploychanges(self):
        logging.log(DOC, """In the deploychanges() method.
This method calls the getdeployabledevices() method to get a list of devices that need deployed.  It then iterates
through that list and send a request to the FMC to push changes to that device.
""")
        url = "/deployment/deploymentrequests"
        devices = self.getdeployabledevices()
        if not devices:
            logging.info("No devices need deployed.\n\n")
            return
        nowtime = int(1000 * datetime.datetime.now().timestamp())
        json_data = {
            'type': 'DeploymentRequest',
            'forceDeploy': True,
            'ignoreWarning': True,
            'version': nowtime,
            'deviceList': []
        }
        for device in devices:
            logging.info("Adding device {} to deployment queue.".format(device))
            json_data['deviceList'].append(device)
        logging.info("Deploying changes to devices.")
        response = self.send_to_api(method='post', url=url, json_data=json_data)
        return response['deviceList']

    # FMC Object Manipulations

    def cleanupexpiredentries(self, **kwargs):
        logging.log(DOC, """In cleanupexpiredentries() method.
This method removes any ACP Rules, Host Objects, and Port Objects that have an expired timestamp value in their name.
""")
        url_search = "/policy/accesspolicies" + "?name=" + kwargs['acp_name']
        response = self.send_to_api(method='get', url=url_search)
        acp_id = None
        if response.get('items', '') is '':
            logging.error("Access Control Policy not found. Exiting.")
            exit(1)
        else:
            acp_id = response['items'][0]['id']
        # Now that we have the ACP ID.  Get all its rules and parse them to look at their names.
        url_search = "/policy/accesspolicies/" + acp_id + "/accessrules"
        response = self.send_to_api(method='get', url=url_search)
        if response.get('items', '') is '':
            logging.warning("No rules found for Access Control Policy: {}.".format(kwargs['acp_name']))
        else:
            for item in response['items']:
                if 'Dev-' in item['name']:
                    namesplit = item['name'].split('-')
                    if int(namesplit[2]) < kwargs['threshold_time']:
                        logging.info("Deleting {} rule from {}.".format(item['name'], kwargs['acp_name']))
                        url = url_search + "/" + item['id']
                        self.send_to_api(method='delete', url=url)
        # Now Delete any expired Host objects.
        url_search = "/object/hosts"
        response = self.send_to_api(method='get', url=url_search)
        for item in response['items']:
            if 'Dev-' in item['name']:
                namesplit = item['name'].split('-')
                if int(namesplit[2]) < kwargs['threshold_time']:
                    logging.info("Deleting {} host object.".format(item['name']))
                    url = url_search + "/" + item['id']
                    self.send_to_api(method='delete', url=url)
        # Finally Delete any expired Port objects.
        url_search = "/object/protocolportobjects"
        response = self.send_to_api(method='get', url=url_search)
        for item in response['items']:
            if 'Dev-' in item['name']:
                namesplit = item['name'].split('-')
                if int(namesplit[2]) < kwargs['threshold_time']:
                    logging.info("Deleting {} port object.".format(item['name']))
                    url = url_search + "/" + item['id']
                    self.send_to_api(method='delete', url=url)

    def createhostobjects(self, hosts):
        logging.log(DOC, """In the createhostobjects() method.
This method is used to create new Host Objects.  It takes in a list of hosts (a list of formatted dictionaries), then
iterates through that list to format the dictionary values into a "JSON" format.  Then this method issues a call to
the send_to_api() method with this formatted information (along with the URL for creating Host Objects).
Once it gets a reply it ensures that there is an 'id' field in the response otherwise output an eror message since
something went wrong.
""")
        logging.info("Creating Host Object.")
        url = "/object/hosts"
        for host in hosts:
            json_data = {
                'name': host['name'],
                'value': host['value'],
                'type': 'Host',
            }
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                host['id'] = response['id']
                logging.info("\tCreated host object: {}.".format(host['name']))
            else:
                logging.error("Creation of host object: {} failed to return an 'id' value.".format(host['name']))

    def createprotocolportobjects(self, protocolports):
        logging.log(DOC, """In the createprotocolportobjects() method.
This method is used to create new Port Objects.  (I'm not sure why the FMC lists 
these as having a type='ProtocolPortObject' when in the FMC GUI they are shown in the Port page.)
This method takes in a list of ports (a list of formatted dictionaries), then iterates through that list to format 
the dictionary values into a "JSON" format.  Then this method issues a call to the send_to_api() method with this 
formatted information (along with the URL for creating Port Objects).  Once it gets a reply it ensures that there is 
an 'id' field in the response otherwise output an eror message since something went wrong.
""")
        logging.info("Creating Protocol Port Object.")
        url = "/object/protocolportobjects"
        for port in protocolports:
            json_data = {
                'name': port['name'],
                'port': port['port'],
                'protocol': port['protocol'],
                'type': 'ProtocolPortObject',
            }
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                port['id'] = response['id']
                logging.info("\tCreated port object: {}.".format(port['name']))
            else:
                logging.error("Creation of port object: {} failed to return an 'id' value.".format(port['name']))

    def createacprules(self, rules):
        logging.log(DOC, """In the createacprules() method.
This method is used to create Access Control Policy rules.  This can be a bit tricky as these rules are a subset of 
an Access Control Policy.  So, we first must ensure that the provided acp_name is a name of an actual ACP.  We then
get that ACP's id.  Now, using the passed dictionary we populate the json_data variable with the appropriate 
information.  This part is also tricky as several items that are needed are actually just reference 'id' values to
something that exists somewhere else in the FMC.
For example, the sourceNetworks and/or destinationNetworks reference either Host, Network, or Range objects that are
stored somewhere else in the FMC.  So, if we see one of those settings defined in the passed dictionary we need to
query the FMC for it's 'id' (since we reference it by name in the dictionary) and then build out that part of the
json_data variable.
Finally, once the json_data variable is fully built we send it, and the url variable, to send_to_api() method.  The
returned response is checked to see that an 'id' value exists, otherwise post an error to the log.
""")
        logging.info("Creating ACP Rules.")
        for rule in rules:
            # Get ACP's ID for this rule
            url_search = "/policy/accesspolicies" + "?name=" + rule['acpName']
            response = self.send_to_api(method='get', url=url_search)
            acp_id = None
            if response.get('items', '') is '':
                logging.error("\tAccess Control Policy not found. Exiting.")
                exit(1)
            else:
                acp_id = response['items'][0]['id']
            # NOTE: This json_data is written specific to match what I'm setting from the acpRuleList.
            # It will need to be updated if/when I create more advanced ACP Rules.
            json_data = {
                'name': rule['name'],
                'action': rule['action'],
                'type': 'AccessRule',
                'enabled': rule['enabled'],
                'sendEventsToFMC': True,
                'logBegin': rule['logBegin'],
                'logEnd': rule['logEnd'],
            }
            if rule.get('ipsPolicy', '') is not '':
                # Currently you cannot query IPS Policies by name.  I'll have to grab them all and filter from there.
                url_search = "/policy/intrusionpolicies"
                response = self.send_to_api(method='get', url=url_search)
                ips_policy_id = None
                for policie in response['items']:
                    if policie['name'] == rule['ipsPolicy']:
                        ips_policy_id = policie['id']
                if ips_policy_id is None:
                    logging.warning("\tIntrusion Policy {} is not found.  Skipping ipsPolicy "
                                    "assignment.\n\t\tResponse:{}".format(policie['name'], response))
                else:
                    json_data['ipsPolicy'] = {
                        'name': rule['ipsPolicy'],
                        'id': ips_policy_id,
                        'type': 'IntrusionPolicy'
                    }
            if rule.get('sourceZones', '') is not '':
                # NOTE: There can be more than one sourceZone so we need to account for them all.
                securityzone_ids = []
                for zone in rule['sourceZones']:
                    url_search = "/object/securityzones" + "?name=" + zone['name']
                    response = self.send_to_api(method='get', url=url_search)
                    if response.get('items', '') is '':
                        logging.warning("\tSecurity Zone {} is not found.  Skipping destination zone "
                                        "assignment.\n\t\tResponse:{}".format(zone['name'], response))
                    else:
                        tmp = {
                            'name': zone['name'],
                            'id': response['items'][0]['id'],
                            'type': 'SecurityZone'
                        }
                        securityzone_ids.append(tmp)
                if len(securityzone_ids) > 0:
                    json_data['sourceZones'] = {
                        'objects': securityzone_ids
                    }
            if rule.get('destinationZones', '') is not '':
                # NOTE: There can be more than one destinationZone so we need to account for them all.
                securityzone_ids = []
                for zone in rule['destinationZones']:
                    url_search = "/object/securityzones" + "?name=" + zone['name']
                    response = self.send_to_api(method='get', url=url_search)
                    if response.get('items', '') is '':
                        logging.warning("\tSecurity Zone {} is not found.  Skipping destination zone "
                                        "assignment.\n\t\tResponse:{}".format(zone['name'], response))
                    else:
                        tmp = {
                            'name': zone['name'],
                            'id': response['items'][0]['id'],
                            'type': 'SecurityZone'
                        }
                        securityzone_ids.append(tmp)
                if len(securityzone_ids) > 0:
                    json_data['destinationZones'] = {
                        'objects': securityzone_ids
                    }
            if rule.get('sourceNetworks', '') is not '':
                # Currently you cannot query Network Objects by name.  I'll have to grab them all and filter from there.
                url_search = "/object/networkaddresses"
                # Grab a copy of the current Network Objects on the server and we will cycle through these for each
                # sourceNetwork.
                response_network_obj = self.send_to_api(method='get', url=url_search)
                network_obj_ids = []
                for network in rule['sourceNetworks']:
                    for obj in response_network_obj['items']:
                        if network['name'] == obj['name']:
                            tmp = {
                                'type': 'Network',
                                'name': obj['name'],
                                'id': obj['id']
                            }
                            network_obj_ids.append(tmp)
                if len(network_obj_ids) < 1:
                    logging.warning("\tNetwork {} is not found.  Skipping source network "
                                    "assignment.\n\t\tResponse:{}".format(rule['name'], response_network_obj))
                else:
                    json_data['sourceNetworks'] = {
                        'objects': network_obj_ids
                    }
            if rule.get('destinationNetworks', '') is not '':
                # Currently you cannot query Network Objects by name.  I'll have to grab them all and filter from there.
                url_search = "/object/networkaddresses"
                # Grab a copy of the current Network Objects on the server and we will cycle through these for each
                # sourceNetwork.
                response_network_obj = self.send_to_api(method='get', url=url_search)
                network_obj_ids = []
                for network in rule['destinationNetworks']:
                    for obj in response_network_obj['items']:
                        if network['name'] == obj['name']:
                            tmp = {
                                'type': 'Network',
                                'name': obj['name'],
                                'id': obj['id']
                            }
                            network_obj_ids.append(tmp)
                if len(network_obj_ids) < 1:
                    logging.warning("\tNetwork {} is not found.  Skipping destination network "
                                    "assignment.\n\t\tResponse:{}".format(rule['name'], response_network_obj))
                else:
                    json_data['destinationNetworks'] = {
                        'objects': network_obj_ids
                    }
            if rule.get('sourcePorts', '') is not '':
                # Currently you cannot query via by name.  I'll have to grab them all and filter from there.
                url_search = "/object/protocolportobjects"
                response_port_obj = self.send_to_api(method='get', url=url_search)
                port_obj_ids = []
                for port in rule['sourcePorts']:
                    for obj in response_port_obj['items']:
                        if port['name'] == obj['name']:
                            tmp = {
                                'type': 'ProtocolPortObject',
                                'name': obj['name'],
                                'id': obj['id'],
                            }
                            port_obj_ids.append(tmp)
                if len(port_obj_ids) < 1:
                    logging.warning("\tPort {} is not found.  Skipping source port "
                                    "assignment.\n\t\tResponse:{}".format(port['name'], response_port_obj))
                else:
                    json_data['sourcePorts'] = {
                        'objects': port_obj_ids
                    }
            if rule.get('destinationPorts', '') is not '':
                # Currently you cannot query via by name.  I'll have to grab them all and filter from there.
                url_search = "/object/protocolportobjects"
                response_port_obj = self.send_to_api(method='get', url=url_search)
                port_obj_ids = []
                for port in rule['destinationPorts']:
                    for obj in response_port_obj['items']:
                        if port['name'] == obj['name']:
                            tmp = {
                                'type': 'ProtocolPortObject',
                                'name': obj['name'],
                                'id': obj['id'],
                            }
                            port_obj_ids.append(tmp)
                if len(port_obj_ids) < 1:
                    logging.warning("\tPort {} is not found.  Skipping destination port "
                                    "assignment.\n\t\tResponse:{}".format(port['name'], response_port_obj))
                else:
                    json_data['destinationPorts'] = {
                        'objects': port_obj_ids
                    }
            # Update URL to be specific to this ACP's ruleset.
            url = "/policy/accesspolicies/" + acp_id + "/accessrules"
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                rule['id'] = response['id']
                logging.info("\tACP Rule {} created.".format(rule['name']))
            else:
                logging.error("Creation of ACP rule: {} failed to return an 'id' value.".format(rule['name']))

    def registerdevices(self, devices):
        logging.log(DOC, """In the registerdevices() method.
This method is used to register new devices with the FMC.  Using the list of dictionaries passed into this method it 
loops through the data to format the json_data variable.  Once set up the json_data and url variables are sent to the
send_to_api() method to tell the FMC to attempt to register this device.
A lot can go wrong here.  For example, I always forget to enable my licensing and/or I forget to issue the command:
"configure manager <ip> <reg key> <nat id>" on the device.  This will mean that the FMC will get this request to
register a device but can't.  Another problem is that the time it takes to fully register a device is LONG.  I don't
know how to deal with that in the middle of a script so typically I just create a unique script that does the 
registrations and then, once I've confirmed the devices are registered, I run another script to program them.
""")
        logging.info("Registering FTD Devices.")
        for device in devices:
            json_data = {
                'type': 'Device',
                'name': device['name'],
                'hostName': device['hostName'],
                'regKey': device['regkey'],
                'version': device['version'],
                'license_caps': device['licenses'],
            }
            # Get ACP's ID for this rule
            url_search = "/policy/accesspolicies" + "?name=" + device['acpName']
            response = self.send_to_api(method='get', url=url_search)
            if response.get('items', '') is '':
                logging.error("\tAccess Control Policy not found. Exiting.")
                continue
            json_data['accessPolicy'] = {
                'name': device['acpName'],
                'id': response['items'][0]['id'],
                'type': 'AccessPolicy'
            }
            url = "/devices/devicerecords"
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('metadata', '') is not '':
                logging.info("\t%s registration can take some time (5 minutes or more)." % device['name'])
                logging.info("\t\tIssue the command 'show managers' on", device['name'], "to view progress.")

    def createsecurityzones(self, zones):
        logging.log(DOC, """In the createsecurityzones() method.
This method is used to create new Security Zones in the FMC.  It accepts a list of python dictionaries that contain
the needed information to build a security zone.  This list is looped through and for each entry a json_data variable
is configured and sent, along with the url variable, to the send_to_api() method to create the zone.  If the returned
response doesn't contain an 'id' value an error is thrown.
""")
        logging.info("Creating Security Zones.")
        url = "/object/securityzones"
        for zone in zones:
            json_data = {
                "type": "SecurityZone",
                "name": zone['name'],
                "description": zone['desc'],
                "interfaceMode": zone['mode'],
            }
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                zone['id'] = response['id']
                logging.info("\tCreated Security Zone {}.".format(zone['name']))
            else:
                logging.error("Creation of Security Zone: {} failed to return an 'id' value.".format(zone['name']))

    def createnetworkobjects(self, objects):
        logging.log(DOC, """In the createnetworkobjects() method.
This method is used to create new Network Objects in the FMC.  It accepts a list of python dictionaries that contain
the needed information to build a network object.  This list is looped through and for each entry a json_data variable
is configured and sent, along with the url variable, to the send_to_api() method to create the object.  If the returned
response doesn't contain an 'id' value an error is thrown.
""")
        logging.info("Creating Network Objects.")
        url = "/object/networks"
        for obj in objects:
            json_data = {
                'name': obj['name'],
                'value': obj['value'],
                'description': obj['desc'],
                'type': 'Network',
            }
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                obj['id'] = response['id']
                logging.info("\tCreated Network Object {}.".format(obj['name']))
            else:
                logging.error("Creation of Network Object: {} failed to return an 'id' value.".format(obj['name']))

    def createurls(self, objects):
        logging.log(DOC, """In the createurls() method.
This method is used to create new URL Objects in the FMC.  It accepts a list of python dictionaries that contain
the needed information to build a url object.  This list is looped through and for each entry a json_data variable
is configured and sent, along with the url variable, to the send_to_api() method to create the object.  If the returned
response doesn't contain an 'id' value an error is thrown.
""")
        logging.info("Creating URL Objects.")
        url = "/object/urls"
        for obj in objects:
            json_data = {
                'name': obj['name'],
                'url': obj['value'],
                'description': obj['desc'],
                'type': 'Url',
            }
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                obj['id'] = response['id']
                logging.info("\tCreated URL Object {}.".format(obj['name']))
            else:
                logging.error("Creation of URL Object: {} failed to return an 'id' value.".format(obj['name']))

    def createacps(self, policies):
        logging.log(DOC, """In the createacps() method.
This method is used to create new Access Control Policy(s) in the FMC.  It accepts a list of python dictionaries that
contain the needed information to build an ACP.  This list is looped through and for each entry a json_data variable
is configured and sent, along with the url variable, to the send_to_api() method to create the object.  If the returned
response doesn't contain an 'id' value an error is thrown.
""")
        logging.info("Creating Access Control Policies.")
        url = "/policy/accesspolicies"
        for policy in policies:
            json_data = {
                'type': "AccessPolicy",
                'name': policy['name'],
                'description': policy['desc'],
            }
            if False and policy.get('parent', '') is not '':
                # Modifying Metatdata is not supported so we cannot create "child" ACPs yet.  :-(
                url_search = url + "?name=" + policy['parent']
                response = self.send_to_api(method='get', url=url_search)
                json_data['metadata'] = {
                    'inherit': True,
                    'parentPolicy': {
                        'type': 'AccessPolicy',
                        'name': policy['parent'],
                        'id': response['items'][0]['id']
                    }
                }
            else:
                json_data['defaultAction'] = {'action': policy['defaultAction']}
            response = self.send_to_api(method='post', url=url, json_data=json_data)
            if response.get('id', '') is not '':
                policy['id'] = response['id']
                logging.info("\tCreated Access Control Policy {}.".format(policy['name']))
            else:
                logging.error("Creation of Access Control Policy: {} failed to return an "
                              "'id' value.".format(policy['name']))

    def modifydevice_physicalinterfaces(self, device_attributes):
        logging.log(DOC, """In the modifydevice_physicalinterfaces() method.
To my knowledge this method doesn't yet work.  :-(
The idea is to be able to set up IP addresses and Zones on a device's interfaces. 
""")
        logging.info("Modifying Physical Interfaces on FTD Devices.")
        # Get ID of this FTD Device first.  Alas, you can't GET by name.  :-(
        url_search = "/devices/devicerecords"
        # Grab a copy of the current Devices on the server so that we can cycle through to find the one we want.
        response_devices = self.send_to_api(method='get', url=url_search)
        if response_devices.get('items', '') is '':
            # It there are no devices (or we can't query them for some reason) none of this will work.
            logging.info("\tQuery for a list of Devices failed.  Exiting.")
            return
        for attribute in device_attributes:
            # Find the Device ID for this set of interfaces.
            device_id = None
            for device in response_devices['items']:
                if device['name'] == attribute['deviceName']:
                    device_id = device['id']
            if device_id is None:
                logging.info("\tDevice {} is not found.  Skipping modifying "
                             "interfaces.".format(attribute['deviceName']))
            else:
                #  Now that we have the device's ID.  Time to loop through our physical interfaces and see if we can
                # match them to this device's interfaces to get an ID.
                for device in attribute['physicalInterfaces']:
                    url = url_search + "/" + device_id + "/physicalinterfaces"
                    url_search2 = url + "?name=" + device['name']
                    response_interface = self.send_to_api(method='get', url=url_search2)
                    if response_interface.get('items', '') is '':
                        logging.info("\tDevice {} has not physical interface "
                                     "named {}.".format(attribute['deviceName'], device['name']))
                    else:
                        # Get the ID for the Security Zone.
                        url_search3 = "/object/securityzones" + "?name=" + device['securityZone']
                        response_securityzone = self.send_to_api(method='get', url=url_search3)
                        if response_securityzone.get('items', '') is '':
                            logging.info("\tSecurity Zone {} is not found.  Skipping modifying interface {} for "
                                         "device {}.".format(device['securityZone'], device['name'],
                                                             attribute['deviceName']))
                        else:
                            # Time to modify this interface's information.
                            json_data = {
                                'type': 'PhysicalInterface',
                                'enabled': True,
                                'name': device['name'],
                                'id': response_interface['items'][0]['id'],
                                'ifname': device['ifName'],
                                'securityZone': {
                                    'id': response_securityzone['items'][0]['id'],
                                    'name': device['securityZone'],
                                    'type': 'SecurityZone'
                                },
                                'ipv4': device['ipv4'],
                            }
                    response = self.send_to_api(method='put', url=url, json_data=json_data)
                    if response.get('metadata', '') is not '':
                        logging.info("\tInterface {} on device {} has been modified.".format(device['name'],
                                                                                             attribute['deviceName']))
                    else:
                        logging.info("\tSomething wrong happened when modifying "
                                     "interface {} on device {}.".format(device['name'], attribute['deviceName']))
