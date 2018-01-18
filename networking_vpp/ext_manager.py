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

import stevedore

class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extensions.

    Note that extensions must be named to be loaded, which avoids
    the situation where an extension that is simply installed
    on the system is pulled in.

    Extensions are expected to hook themselves into code
    and to each other as they are intialised.
    """

    def __init__(self, ext_entrypoint, extension_names, extension_class):
        # Registered drivers, keyed by name.
        # Extensions may refer to one another, and this makes that possible.
        self._extensions = {}

        LOG.info("Extension type %s: requested %s",
                 ext_entrypoint, extension_names)
        super(MechanismManager, self).__init__(
            ext_entrypoint,
            extension_names,
            invoke_on_load=True,
            name_order=True,
            on_missing_entrypoints_callback=self._driver_not_found,
            on_load_failure_callback=self._driver_not_loaded
        )
        LOG.info("Loaded names: %s", self.names())
        for ext in self:
            assert isinstance(ext.obj, extension_class)
            self._extensions[ext.name] = ext.obj

        # Initialise in found order
        # Allow cross-referencing by offering up self
        # (for its .get_extension method)
        self.call_all('initialize', self)

    def call_all(self, method, *args, **kwargs):
        for ext in self:
            getattr(ext.obj, method)(*args, **kwargs)

    def get_extension(self, name):
        return self._extensions[name]

    def _driver_not_found(self, names):
        msg = (_("The following networking-vpp plugins were not found: %s")
               % names)
        LOG.critical(msg)
        raise SystemExit(msg)

    def _driver_not_loaded(self, manager, entrypoint, exception):
        LOG.critical("The '%(entrypoint)s' entrypoint could not be"
                     " loaded for the following reason: '%(reason)s'.",
                     {'entrypoint': entrypoint,
                      'reason': exception})
        raise SystemExit(str(exception))
