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
import pynetbox, pyeapi
import pyeapi
import pprint


# Netbox URL to use
NETBOX_URL = 'http://netbox.as73.inetsix.net'
# Netbox Token to authenticate against NETBOX_URL
NETBOX_TOKEN = 'd02bc3922f88f28e48fc66e9a3b3c8e3eab7a79a'
# Tag configured on prefixes to scan
TAG_FOR_SCAN = 'unset'

EOS_USERNAME = 'admin'
EOS_PASSWORD = 'arista123'


def query_eos(host, command):
    device = pyeapi.connect(host=host, transport='https', username=EOS_USERNAME, password=EOS_PASSWORD)
    return device.execute(['enable', command])['result'][1]


def extract_vrf_name(eos_json):
    return [k for k, v in eos_json['vrfs'].items()]


if __name__ == '__main__':

    pp = pprint.PrettyPrinter(indent=4)
    nb = pynetbox.api(url=NETBOX_URL, token=NETBOX_TOKEN)
    nb.http_session.verify = False
    devices = nb.dcim.devices.filter(platform='eos')
    for device in devices:
        # pp.pprint(dict(device))
        discovered_device_ip = str(device.primary_ip.address).split('/')[0]
        discovered_tenant = str(device.tenant.id)
        print(f"Connecting to device {device.display} using its IP {discovered_device_ip}")
        eos_vrf = query_eos(host=discovered_device_ip, command='show vrf')
        pp.pprint(eos_vrf)
        print(f"List of vrfs is: {extract_vrf_name(eos_json=eos_vrf)}")
        for vrf in extract_vrf_name(eos_vrf):
            if vrf != 'default':
                if len(nb.ipam.vrfs.filter(q=vrf, tenant=str(device.tenant.name))) == 0:
                    print('Adding VRF {vrf} to netbox')
                    nb.ipam.vrfs.create(name=vrf, comments=f'found in {device}/{discovered_device_ip}', tenant=discovered_tenant)
                else:
                    print('VRF is present. Update process could be implemented if required')