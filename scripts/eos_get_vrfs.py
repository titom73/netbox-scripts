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
import ssl
import pynetbox
import pyeapi
from extras.scripts import *

"""
Netbox Script to inject VRFs configured on EOS devices

Description
-----------

It gets all EOS devices and search for VRF to create on Netbox:
- If VRF is not existing, then create
- Guess tenant from tenant configured on device
- Do not update if VRF exists in Netbox

Requirements
------------

- pyeapi (git version as of March 2023)
- pynetbox
"""

# Netbox URL to use
NETBOX_URL = 'http://netbox.as73.inetsix.net'
# Netbox Token to authenticate against NETBOX_URL
NETBOX_TOKEN = '<must be set>'
# Tag configured on prefixes to scan
TAG_FOR_SCAN = 'vrfscan'

# Required to fix CIPHER issue with py3.10
# https://arista.my.site.com/AristaCommunity/s/article/Python-3-10-and-SSLV3-ALERT-HANDSHAKE-FAILURE-error
# Use TLSv1.2
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Using the EOS default ciphers
context.set_ciphers('AES256-SHA:DHE-RSA-AES256-SHA:AES128-SHA:DHE-RSA-AES128-SHA')


class EosVrf(Script):
    class Meta:
        name = 'Populate VRFs from Arista EOS'
        description = 'Get all VRFs configured on all devices running Arista / EOS'

    eos_username = StringVar(description="Username to use to connect to EOS", default='admin')
    eos_password = StringVar(description="Password to use to connect to EOS", default='arista123')

    def query_eos(self, host, command, eos_username, eos_password):
        device = pyeapi.client.connect(
            host=host,
            transport='https',
            username=eos_username,
            password=eos_password,
            context=context
        )
        return device.execute(['enable', command])['result'][1]


    def extract_vrf_name(self, eos_json):
        return [k for k, v in eos_json['vrfs'].items()]


    def run(self, data: Any, commit: bool) -> None:
        nb = pynetbox.api(url=NETBOX_URL, token=NETBOX_TOKEN)
        nb.http_session.verify = False
        devices = nb.dcim.devices.filter(platform='eos')
        for device in devices:
            discovered_device_ip = str(device.primary_ip.address).split('/')[0]
            discovered_tenant = str(device.tenant.id)
            self.log_info(f"Connecting to device {device.display} using its IP {discovered_device_ip}")
            eos_vrf = self.query_eos(host=discovered_device_ip, command='show vrf', eos_username=data['eos_username'], eos_password=data['eos_password'])
            self.log_info(f"List of vrfs is: {self.extract_vrf_name(eos_json=eos_vrf)}")
            for vrf in self.extract_vrf_name(eos_vrf):
                if vrf != 'default':
                    if len(nb.ipam.vrfs.filter(q=vrf, tenant=str(device.tenant.name))) == 0:
                        self.log_success(f'Adding VRF {vrf} to netbox')
                        nb.ipam.vrfs.create(name=vrf, comments=f'found in {device}/{discovered_device_ip}', tenant=discovered_tenant)
                    else:
                        self.log_warning('VRF is present. Update process could be implemented if required')
