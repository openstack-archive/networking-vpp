# Copyright (c) 2013 OpenStack Foundation
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

# Derived from the Neutron ML2 plugin's driver loading code.

import logging
import stevedore

import networking_vpp.extension

LOG = logging.getLogger(__name__)


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extensions.

    Note that extensions must be named to be loaded, which avoids
    the situation where an extension that is simply installed
    on the system is pulled in.

    Extensions are expected to hook themselves into code
    and to each other as they are intialised.

    ext_entrypoint: the label of the entry point
    extension_names: a comma separated list of extensions
    extension_class: the class type the extension is expected to be
    system_hooks: a set of hooks that the hosting system provides
        to extensions.  May be attached to in the init phase so must
        be available up front.
    """

    def __init__(self, ext_entrypoint, extension_names, extension_class,
                 system_hooks=networking_vpp.extension.HookManager()):
        # Registered drivers, keyed by name.
        # Extensions may refer to one another, and this makes that possible.
        self._extensions = {}

        self.ext_entrypoint = ext_entrypoint
        self.system_hook_manager = system_hooks

        if extension_names == '':
            name_list = []
        else:
            name_list = extension_names.split(',')

        LOG.debug("###Extension type %s: requested %s",
                  ext_entrypoint, extension_names)
        super(ExtensionManager, self).__init__(
            ext_entrypoint,
            name_list,
            invoke_on_load=True,
            name_order=True,
            on_missing_entrypoints_callback=self._driver_not_found,
            on_load_failure_callback=self._driver_not_loaded
        )
        LOG.debug("Loaded names: %s", self.names())
        for ext in self:
            assert isinstance(ext.obj, extension_class)
            self._extensions[ext.name] = ext.obj

        # Initialise in found order
        # Allow cross-referencing by offering up self
        # (for its .get_extension / attach__hook method)
        self.call_all('initialize', self)

    def call_all(self, method, *args, **kwargs):
        for ext in self:
            getattr(ext.obj, method)(*args, **kwargs)

    def get_extension(self, name):
        return self._extensions[name]

    def attach_hook(self, ext_name, hook_name, fn):
        if ext_name is None:
            self.system_hooks.attach(fn)
        else:
            self.get_extension(ext_name).hooks.attach(hook_name, fn)

    def _driver_not_found(self, names):
        LOG.critical("networking-vpp %s extensions not found: %s",
                     self.ext_entrypoint, names)
        raise SystemExit()

    def _driver_not_loaded(self, manager, name, exception):
        LOG.critical("The %(kind)s '%(name)s' entrypoint could not be"
                     " loaded for the following reason: '%(reason)s'.",
                     {'kind': self.ext_entrypoint,
                      'name': name,
                      'reason': exception})
        raise SystemExit(str(exception))
