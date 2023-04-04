#!/usr/bin/python
# coding: utf-8 -*-
#
# Copyright 2023 Arista Networks Thomas Grimonet
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http: //www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from typing import Any
import pynetbox, urllib3, networkscan, socket, ipaddress
from extras.scripts import Script

"""
Netbox Script to scan prefixes and update IP address status

Description
-----------

It gets all prefixes configured in netbox and if tag <TAG_FOR_SCAN> is configured, then scan all ip_addresses
- If host is UP: mark IP as active
- If host is Down and already configured, mark IP as deprecated
- Try to resolve DNS to report in netbox
- Get VRF from that prefix and configure IP address in this VRF.

Requirements
------------

- ipcalc
- networkscan
- pynetbox

inetutils-ping MUST be installed in your netbox environment

Unsupported features
--------------------

- IP addresses in different VRFs.
"""

# Netbox URL to use
NETBOX_URL = 'http://netbox.as73.inetsix.net'
# Netbox Token to authenticate against NETBOX_URL
NETBOX_TOKEN = ''
# Tag configured on prefixes to scan
TAG_FOR_SCAN = 'ipscan'


class IpScan(Script):
    class Meta:
        name = 'Netbox IP Scanner'
        description = 'Scans prefixes configured in Netbox and updates IP Address under IPAM module'

    def run(self, data: Any, commit: bool) -> None:
        def do_rdns(ip) -> str:
            """
            Execute reverse-dns query to discover hostname for IP address

            Args:
                ip (str): IP address to resolv

            Returns:
                str: Hostname configured for IP address (PTR)
            """
            try:
                data = socket.gethostbyaddr(ip)
            except Exception:
                return '' # fails gracefully
            return '' if data[0] == '' else data[0]

        nb_instance = pynetbox.api(url=NETBOX_URL, token=NETBOX_TOKEN)
        nb_instance.http_session.verify = False
        self.log_warning('connecting to netbox')
        # get all available subnets
        prefixes = nb_instance.ipam.prefixes.all()
        for prefix in prefixes:
            is_scannable = False
            for tag in prefix.tags:
                is_scannable = True if str(tag).lower() == str(TAG_FOR_SCAN).lower() else is_scannable
            if is_scannable:
                self.log_info(f'scanning prefix {prefix} since tag {TAG_FOR_SCAN} is configured')
                # get VRF configured for the prefix
                configured_vrf = str(prefix.vrf) if prefix.vrf is not None else ''

                ipv4network = ipaddress.IPv4Network(prefix)
                scan = networkscan.Networkscan(prefix)

                # run network scan. require inetutils-ping to be installed on runner
                scan.run()
                self.log_info(f'scan of subnet {prefix} done.')
                if scan.list_of_hosts_found == []:
                    self.log_warning(f'No host found in network {prefix}')
                else:
                    self.log_success(f'IPs found: {scan.list_of_hosts_found}')

                # Monitor IP address status from Network to Netbox
                for address_scanned in scan.list_of_hosts_found:
                    address_scanned_cidr = f'{address_scanned}/{ipv4network.prefixlen}'
                    address_netbox_info = nb_instance.ipam.ip_addresses.get(address=address_scanned_cidr)
                    # If IP already exist in Netbox
                    if address_netbox_info != None:
                        state = 'reserved'
                        # If present in scan list, mark it as active.
                        if str(address_netbox_info).rpartition('/')[0] in scan.list_of_hosts_found:
                            self.log_info(f'Host {address_netbox_info} is responding. updating state to active')
                            state = 'active'
                        # If present in Netbox but not in scan result
                        # Mark it as deprecated
                        else:
                            self.log_warning(f'Host {address_netbox_info} is not responding. updating state to deprecated')
                            state = 'deprecated'
                        nb_instance.ipam.ip_addresses.update([{'id':address_netbox_info.id, 'status':state, 'vrf': nb_instance.ipam.vrfs.get(q=configured_vrf).id},])

                # Update or Create entry in Netbox with their hostname
                for address_scanned in scan.list_of_hosts_found:
                    address_scanned_cidr = f'{address_scanned}/{ipv4network.prefixlen}'
                    address_netbox_info = nb_instance.ipam.ip_addresses.get(address=address_scanned_cidr)
                    if address_netbox_info != None:
                        rdns = do_rdns(address_scanned)
                        if address_netbox_info.dns_name != rdns:
                            self.log_info(f'Updating netbox entry for {address_scanned_cidr} (dns: {rdns})')
                            nb_instance.ipam.ip_addresses.update([{'id':address_netbox_info.id, 'dns_name':rdns},])
                    else:
                        rdns = do_rdns(address_scanned_cidr)
                        self.log_info(f'Adding {address_scanned_cidr} to netbox')
                        result = nb_instance.ipam.ip_addresses.create(address=address_scanned_cidr, status='active', dns_name=rdns)
                        if result:
                            result.vrf = nb_instance.ipam.vrfs.get(q=configured_vrf).id
                            result.save()
                            self.log_info(f'netbox entry for {address_scanned_cidr} (dns:{rdns}) created')
                        else:
                            self.log_error(f'netbox entry for {address_scanned_cidr} (dns:{rdns}) Failed')
