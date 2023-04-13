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
import ipaddress
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
NETBOX_TOKEN = 'd02bc3922f88f28e48fc66e9a3b3c8e3eab7a79a'
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
                configured_tenant = str(prefix.tenant)
                self.log_info(f'Network is configured in vrf {configured_vrf} for tenant {configured_tenant}')

                ipv4network = ipaddress.IPv4Network(prefix)
                scan = networkscan.Networkscan(prefix)

                # run network scan. require inetutils-ping to be installed on runner
                scan.run()
                self.log_info(f'scan of subnet {prefix} done.')
                if scan.list_of_hosts_found == []:
                    self.log_warning(f'No host found in network {prefix}')
                else:
                    self.log_info(f'Found: {len(scan.list_of_hosts_found)} IPs in {prefix}')
                    self.log_info(f'-> {scan.list_of_hosts_found}')

                # Build a list of IP to update
                # Concatenate live host and Netbox configured hosts
                netbox_addresses = [
                    str(nb_address).split('/')[0] for nb_address in nb_instance.ipam.ip_addresses.all()
                    if ipaddress.ip_address(str(nb_address).split('/')[0]) in ipaddress.ip_network(prefix)
                ]
                # netbox_addresses = [str(address).split('/')[0] for address in nb_instance.ipam.ip_addresses.filter(parent=prefix)]
                ips_to_check = list(set(scan.list_of_hosts_found + netbox_addresses))
                self.log_info(f'Need to work on: {len(ips_to_check)} IPs in {prefix}')
                self.log_info(f'-> {ips_to_check}')
                self.log_info(f'Netmask to use: {ipv4network.prefixlen}')


                # Monitor IP address status from Network to Netbox
                for address_scanned in ips_to_check:
                    # Build CIDR format as it is used by Netbox
                    address_scanned_cidr = f'{address_scanned}/{ipv4network.prefixlen}'
                    # Get Netbox information for given IP Address
                    address_netbox_info = nb_instance.ipam.ip_addresses.get(
                        address=address_scanned_cidr,
                        # vrf=nb_instance.ipam.vrfs.get(q=configured_vrf)
                    )
                    # Execute reverse DNS check for IP address
                    rdns = do_rdns(address_scanned)

                    self.log_debug(f'Netbox info for host {address_scanned} is {address_netbox_info}')

                    if  address_netbox_info is None:
                        self.log_debug(f'Creating entry for address {address_scanned_cidr} in netbox in tenant {configured_tenant}')
                        result = nb_instance.ipam.ip_addresses.create(address=address_scanned_cidr, status='active')
                        result.vrf = nb_instance.ipam.vrfs.get(q=configured_vrf).id
                        result.save()
                        address_netbox_info = nb_instance.ipam.ip_addresses.get(
                            address=address_scanned_cidr,
                            # vrf=nb_instance.ipam.vrfs.get(q=configured_vrf)
                        )

                    # If IP already exist in Netbox
                    if address_netbox_info != None:
                        # self.log_debug(f'got {address_netbox_info} to deal with')
                        state = 'reserved'
                        # If present in scan list, mark it as active.
                        if str(address_netbox_info).split('/')[0] in scan.list_of_hosts_found:
                            state = 'active'
                        # If present in Netbox but not in scan result
                        # Mark it as deprecated
                        else:
                            self.log_warning(f'Host {address_netbox_info} is not responding. updating state to deprecated')
                            state = 'deprecated'

                        # Update IP address in Netbox
                        nb_instance.ipam.ip_addresses.update(
                            [
                                {'id':address_netbox_info.id,
                                 'status':state,
                                 'vrf': nb_instance.ipam.vrfs.get(q=configured_vrf).id,
                                 'dns_name':rdns,
                                 'tenant': nb_instance.tenancy.tenants.get(q=configured_tenant).id,
                                },
                            ]
                        )
                    else:
                        self.log_warning(f'skipping {address_netbox_info}')

