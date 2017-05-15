#! /usr/bin/env python
__author__ = 'michaelluich'
author_email = 'mluich@stonesrose.com',

import json
import inspect
import logging

from requests.auth import HTTPBasicAuth
from requests import get, post, patch, delete
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3 import exceptions

disable_warnings(exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class PhpIPAM:
    """An interface to phpIPAM web API."""

    def __init__(self, server, app_id, username, password, ssl_verify=False, debug=False):
        """
        :param server: the base server location.
        :param app_id: the app ID to access
        :param username: username
        :param password: password
        :param ssl_verify: should the certificate being verified
        :param debug: debug
        """
        self.error = 0
        self.error_message = ""
        self.server = server
        self.app_id = app_id
        self.username = username
        self.password = password
        self.appbase = "{}/api/{}".format(self.server, self.app_id)
        self.ssl_verify = ssl_verify
        self.token = None
        if debug:
            self.enable_debug()
        self.login()

    @staticmethod
    def enable_debug():
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client

        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def __query(self, entrypoint, method=get, data=None, auth=None):
        headers = {}
        if self.token:
            headers['token'] = self.token
        if data != None:
            if type(data) != str:
                data = json.dumps(data)
            headers['Content-Type'] = 'application/json'
            if method == get:
                method = post

        p = method(
            self.appbase + entrypoint,
            data=data,
            headers=headers,
            auth=auth,
            verify=self.ssl_verify
        )
        response = json.loads(p.text)
        callingfct = inspect.getouterframes(inspect.currentframe(), 2)[1][3]

        if not p.status_code in (200, 201):
            logging.error("phpipam.{}: Failure {}".format(callingfct, p.status_code))
            logging.error(response)
            self.error = p.status_code
            self.error_message = response['message']
            raise exceptions.HTTPError(response=response)

        if not response['success']:
            logging.error("phpipam.{}: FAILURE: {}".format(callingfct, response['code']))
            self.error = response['code']
            raise exceptions.HTTPError(response=response)

        logging.info("phpipam.{}: success {}".format(callingfct, response['success']))
        return response['data']

    # Authentication

    def login(self):
        """Login to phpIPAM and get a token."""
        ticket_json = self.__query('/user/', auth=HTTPBasicAuth(self.username, self.password), method=post)
        # Ok So now we have a token!
        self.token = ticket_json['token']
        self.token_expires = ticket_json['expires']
        logging.info("phpipam.login: Sucessful Login to {}".format(self.server))
        logging.debug("phpipam.login: IPAM Ticket expiration: {}".format(self.token_expires))
        return {"expires": self.token_expires}

    def ticket_check(self):
        """"check if a ticket is still valid"""
        try:
            return self.__query("/user/")
        except:
            return self.login()

    def ticket_extend(self):
        """Extends ticket duration (ticket last for 6h)"""
        return self.__query("/user/")

    # Authorization

    def authorization(self, controller):
        """Check the authorization of a controller and get a list of methods"""
        return self.__query("/{}/".format(controller))['methods']

    ### Controllers

    ## Sections

    def sections_get_all(self):
        """Get a list of all sections"""
        return self.__query("/sections/?links=false")

    def sections_get_id(self, section):
        """Get the ID of a section

        Parameters:
            section: The name of the section you are looking for
        """
        return self.__query("/sections/{}/?links=false".format(section))['id']

    def sections_get(self, section_id):
        """Get the details for a specific section

        Parameters:
            section_id = section identifier. Can be the id number or name.
        """
        return self.__query("/sections/{}/?links=false".format(section_id))

    def sections_get_subnets(self, section_id):
        """Get the subnets for a specific section

         Parameters:
             section_id = section identifier. Can be the id number or name.
         """
        return self.__query("/sections/{}/subnets/?links=false".format(section_id))

    def sections_create(self, section_id, masterSection=0):
        """Create a section

         Parameters:
             section_id = section name.
         """
        data = {'name': section_id}
        if masterSection != 0: data['masterSection'] = masterSection
        return self.__query("/sections/", data=data)

    def sections_delete(self, section_id, ):
        """Delete a section

        Parameters:
        section_id = section name or id.
        """
        return self.__query("/sections/{}/".format(section_id), method=delete)

    ## Subnet

    def subnet_get(self, subnet_id):
        """Get Information about a specific subnet

        Parameters:
        subnet_id: The subnet identifier either the ID or cidr
        """
        return self.__query("/subnets/{}/?links=false".format(subnet_id))

    def subnet_search(self, subnet_id):
        """Search by cidr

        Parameters:
        subnet_id: The subnet cidr
        """
        return self.__query("/subnets/cidr/{}/?links=false".format(subnet_id))

    def subnet_all(self, subnet_id):
        """Get all addresses in a subnet

        Parameters:
        subnet_id: The subnet id
        """
        return self.__query("/subnets/{}/addresses/?links=false".format(subnet_id))

    def subnet_first_available(self, subnet_id):
        """Get first available

        Parameters:
        subnet_id: The subnet id
        """
        return self.__query("/subnets/{}/first_free/?links=false".format(subnet_id))

    def subnet_create(self, subnet, mask, sectionId, description="", vlanid=None, mastersubnetid=0, nameserverid=None):
        """Create new subnet

        Parameters:
        subnet: The subnet
        mask: the subnet mask
        sectionId
        description: description
        vlanid:
        mastersubnetid:
        nameserverid:"""
        data = {
            'subnet': subnet,
            'mask': mask,
            "sectionId": sectionId,
            'description': description,
            'vlanId': vlanid,
            'masterSubnetId': mastersubnetid,
            'nameserverId': nameserverid
        }
        return self.__query("/subnets/", data=data)

    def subnet_delete(self, subnet_id, ):
        """Delete a subnet

        Parameters:
        subnet_id = subnet name or id.
        """
        return self.__query("/subnets/{}/".format(subnet_id), method=delete)

    ## Address

    def address_get(self, address_id):
        """Get Information about a specific address

        Parameters:
        address_id: The address identifier either the ID or cidr
        """
        return self.__query("/addresses/{}/?links=false".format(address_id))

    def address_search(self, address):
        """Search for a specific address

        Parameters:
        address: The address identifier either the ID or address
        """
        return self.__query("/addresses/search/{}/?links=false".format(address))

    def address_update(self, ip, hostname=None, description=None, is_gateway=None, mac=None):
        """Update address informations"""
        orgdata = self.address_search(ip)[0]
        data = {}
        if hostname:
            data["hostname"] = hostname
        if description:
            data["description"] = description
        if is_gateway:
            data["is_gateway"] = is_gateway
        if mac:
            data["mac"] = mac
        return self.__query("/addresses/{}/".format(orgdata['id']), method=patch, data=data)

    def address_create(self, ip, subnet_id, hostname, description="", is_gateway=0, mac=""):
        """Create new address

        Parameters:
        number: address number
        name: short name
        description: description"""
        data = {
            "ip": ip,
            "subnetId": subnet_id,
            "hostname": hostname,
            "description": description,
            "is_gateway": is_gateway,
            "mac": mac,
        }
        return self.__query("/addresses/", data=data)

    ## VLAN

    def vlan_get(self, vlan_id):
        """Get Information about a specific vlan

        Parameters:
        vlan_id: The vlan identifier either the ID or cidr
        """
        return self.__query("/vlans/{}/?links=false".format(vlan_id))

    def vlan_get_id(self, vlan_id):
        """vlan_get_id
        search for the ID of a vlan.

        Parameters:
        vlan: The vlan to search for
        """
        return self.__query("/vlans/search/{}/?links=false".format(vlan_id))[0]['id']

    def vlan_subnets(self, vlan_id):
        """Get vlan subnets

        Parameters:
        vlan_id: The vlan identifier
        """
        return self.__query("/vlans/{}/subnets/?links=false".format(vlan_id))

    def vlan_create(self, number, name, description=""):
        """Create new vlan

        Parameters:
        number: vlan number
        name: short name
        description: description
        """
        data = {
            'number': number,
            'name': name,
            'description': description,
        }
        return self.__query("/vlans/", data=data)

    def vlan_delete(self, vlan_id, ):
        """Delete a vlan

        Parameters:
        vlan_id = vlan name or id.
        """
        return self.__query("/vlans/{}/".format(vlan_id))
