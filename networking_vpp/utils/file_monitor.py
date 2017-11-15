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
import eventlet_inotifyx as einotify
import os

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# Inotify mask values
IN_CREATE = 256
IN_DELETE = 512


class FileMonitor(object):
    def __init__(self):
        self.devices = set()
        # List of callback functions to be executed on device add/delete events
        self.on_add_cbs = []
        self.on_del_cbs = []
        self.tracked_files = []
        self.watch_dir = cfg.CONF.ml2_vpp.vhost_user_dir
        self.watch_events = [IN_CREATE, IN_DELETE]
        self.watch_file_pattern = [
            '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}']

    def _file_added(self, filename):
        # When a new file is added, we run all the registered add callbacks
        for func in self.on_add_cbs:
            LOG.info("_file_added processing with args %s", filename)
            # TODO(Hareesh): It would better to have some additional exception
            # handling if the called function throws an exception, but in this
            # case we are not sure what to do. Retry or simply ignore it?
            func(filename)
            self.tracked_files.append(filename)
        LOG.debug("Current tracked files: %s", self.tracked_files)

    def _file_deleted(self, filename):
        if filename in self.tracked_files:
            self.tracked_files.remove(filename)
            LOG.info("File %s removed from tracked file index", filename)

    def register_on_add_cb(self, func):
        self.on_add_cbs.append(func)

    def _create_index(self):
        self.tracked_files = [f for f in os.listdir(self.watch_dir)
                              if self._match_pattern(f)]

    def _match_pattern(self, text):
        import re
        for pattern in self.watch_file_pattern:
            if re.search(r'%s' % pattern, text):
                return True
        # No match found
        return False

    def run_inotifyx(self):
        LOG.debug("File Monitor [inotifyx] started")
        try:
            self._create_index()
            LOG.debug("Current tracked files: %s", self.tracked_files)
            fd = einotify.init()
            wd = einotify.add_watch(fd, self.watch_dir)
            while True:
                try:
                    eventlet.sleep()
                    LOG.debug("Entered vhost socket file detect loop")
                    events = einotify.get_events(fd)
                    for event in events:
                        name, mask = event.name, event.mask
                        if not self._match_pattern(name):
                            LOG.debug("Event for name: %s did not match"
                                      "vhost socket name pattern. Ignoring",
                                      name)
                            continue
                        if mask not in self.watch_events:  # CREATE event
                            LOG.debug("EventMask: %s not in %s. Ignoring. "
                                      "Name: %s", str(mask), self.watch_events,
                                      name)
                            continue
                        if mask == IN_CREATE:
                            LOG.info("Vhost socket file: %s with event: %s "
                                     "detected.", name, str(mask))
                            self._file_added(name)
                        if mask == IN_DELETE:
                            LOG.info("Vhost socket file: %s with event: %s "
                                     "detected.", name, str(mask))
                            self._file_deleted(name)
                        # TODO(Hareesh): handle overflow event here.
                        # This should compare the current index and filesystem
                        # to detect and handle any missed file creations.
                except Exception as e:
                    LOG.warning("Ignoring exception. Exception is: %s. ", e)
        except Exception as e:
            LOG.error(e)
        finally:
            einotify.rm_watch(fd, wd)
            os.close(fd)

    run = run_inotifyx

if __name__ == "__main__":
    DOMAIN = "demo"
    logging.register_options(cfg.CONF)
    logging.setup(cfg.CONF, DOMAIN)
    f = FileMonitor()
    eventlet.spawn_n(f.run)
    while True:
        LOG.debug("Looping..")
        eventlet.sleep(seconds=5)
