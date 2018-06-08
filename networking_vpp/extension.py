# Copyright (c) 2018 Cisco Systems, Inc.
# All Rights Reserved.
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

import abc
import six


class HookManager(object):
    """Extension hooks

    An extension may provide hook-in points where specific events
    within the extension can be tapped into.  Initialisation of an
    extension creates a list of hooks in its __init__ call, and
    after all extension have been created all extensions will
    receive an 'initialize' call that will allow each extension
    to hook into the hook points provided by others or by
    the base system.

    The entity hosting the extension may also provide hooks.
    """

    def __init__(self):
        self.hooks = {}

    def call(self, name, *args, **kwargs):
        for f in self.hooks[name]:
            f(*args, **kwargs)

    def create(self, name):
        """Called by an extension to advertise a hook"""
        self.hooks[name] = []

    def attach(self, name, call):
        """Called by an extension to use a hook from another"""
        self.hooks[name].append(call)


@six.add_metaclass(abc.ABCMeta)
class ExtensionBase(object):
    def __init__(self):
        self.hooks = HookManager()

    def deps(self):
        """List of plugin dependencies by name

        This plugin requires the dependencies, and may hook to
        them.

        """
        return []

    def initialize(self, manager):
        """Add cross-references to other extensions if required"""
        pass


@six.add_metaclass(abc.ABCMeta)
class VPPAgentExtensionBase(ExtensionBase):

    @abc.abstractmethod
    def run(self, host, client_factory, vpp_forwarder):
        """Begin threads watching etcd."""
        pass


@six.add_metaclass(abc.ABCMeta)
class MechDriverExtensionBase(ExtensionBase):

    @abc.abstractmethod
    def run(self, communicator):
        pass
