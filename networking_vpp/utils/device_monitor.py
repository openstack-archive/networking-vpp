# Copyright (c) 2017 Cisco Systems, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import eventlet
import pyudev
import select


class DeviceMonitor(object):
    def __init__(self):
        self.devices = set()
        # List of callback functions to be executed on device add/delete events
        self.add_cb = []
        self.del_cb = []

    def _dev_add(self, dev_name):
        # When a new device is added, we run all the registered add callbacks
        for f in self.add_cb:
            f(dev_name)

    def _dev_del(self, dev_name):
        # When a device is deleted, we run all the registered del callbacks
        for f in self.del_cb:
            f(dev_name)

    def on_add(self, func):
        self.add_cb.append(func)

    def on_del(self, func):
        self.del_cb.append(func)

    def run(self):
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='net')
        monitor.start()

        # Initial replay on existing interfaces
        for device in context.list_devices(subsystem='net'):
            self._dev_add(device.sys_name)
            self.devices.add(device.sys_name)

        while True:
            # monitor.poll() is synchronized call, which will block eventlet
            # for certain time. So use select to avoid the stall.
            ready, _, _ = select.select([monitor.fileno()], [], [], 10)
            if ready:
                try:
                    # This will work with pyudev >= v0.16
                    device = monitor.poll(timeout=1)
                    action = device.action
                except AttributeError as ex:
                    # This will work with pyudev <= v0.15
                    action,device = monitor.receive_device()
                if action == 'add':
                    self._dev_add(device.sys_name)
                    self.devices.add(device.sys_name)
                elif action == 'remove':
                    self._dev_del(device.sys_name)
                    self.devices.remove(device.sys_name)
            else:
                eventlet.sleep()
