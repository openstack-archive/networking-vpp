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


import os
import re

import pyinotify

from networking_vpp.utils.pyinotify_eventlet_notifier import (
    Notifier as eventlet_Notifier)
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# Inotify mask values
IN_CREATE = 256
IN_DELETE = 512


class FileMonitor(object):

    """File event monitoring utility class.

    A basic file event monitoring utility built on pyinotify.
    Watches the directory `watch_dir` for file events.
    File name should match regex specified in the watch_pattern attribute.

    If file name pattern matches and it is a CREATE event (i.e. a new file),
    on_add_callbacks are executed passing the file name as argument.
    The same for delete events also.

    We also create an index of existing files on the watched directory.
    Create/delete events update this index.

    No recursion on the watched directory.

    """

    def __init__(self, watch_pattern, watch_dir):
        self.devices = set()
        self.on_add_cbs = []   # Callbacks for on_create event
        self.on_del_cbs = []
        self.tracked_files = []
        self.watch_dir = watch_dir
        self.watch_pattern = watch_pattern

    def _file_added(self, filename):
        # When a new file is added, we run all the registered add callbacks
        for func in self.on_add_cbs:
            LOG.debug("_file_added processing with args %s", filename)
            # TODO(Hareesh): It would better to have some additional exception
            # handling if the called function throws an exception, but in this
            # case we are not sure what to do. Retry or simply ignore it?
            if filename not in self.tracked_files:
                func(filename)
                self.tracked_files.append(filename)
                LOG.info("File: %s CREATE event processed", filename)
                LOG.debug("Current tracked files: %s", self.tracked_files)

    def _file_deleted(self, filename):
        if filename in self.tracked_files:
            for func in self.on_del_cbs:
                func(filename)
            self.tracked_files.remove(filename)
            LOG.info("File %s removed from tracked file index", filename)

    def register_on_add_cb(self, func):
        self.on_add_cbs.append(func)

    def register_on_del_cb(self, func):
        self.on_del_cbs.append(func)

    def _create_index(self):
        self.tracked_files = [f for f in os.listdir(self.watch_dir)
                              if self._match_pattern(f)]

    def _match_pattern(self, text):
        if text is not None:
            return True if re.match('%s' % self.watch_pattern, text) else False

    def run(self):

        LOG.debug("File Monitor [pynotify] entered")

        self._create_index()
        LOG.debug("Current tracked files: %s", self.tracked_files)

        def on_notified(event):
            try:
                LOG.debug("Notified: %s", event)
                name = os.path.basename(event.pathname)
                if not self._match_pattern(name):
                    LOG.debug("Name %s did NOT match watch pattern", name)
                    return
                LOG.debug("File: %s maskname: %s matched watch pattern", name,
                          event.maskname)
                if event.mask & pyinotify.IN_CREATE:
                    LOG.debug("IN_CREATE event for file %s ", name)
                    self._file_added(name)
                if event.mask & pyinotify.IN_DELETE:
                    LOG.debug("IN_DELETE event for file %s", name)
                    self._file_deleted(name)
                if event.mask & pyinotify.IN_Q_OVERFLOW:
                    # TODO(Hareesh): Handle overflow scenarios
                    pass
            except Exception as e:
                LOG.exception("Hit exception but still proceeding. "
                              "Exception is: %s. ", e)

        wm = pyinotify.WatchManager()  # Watch Manager
        while True:
            try:
                mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE
                self.notifier = eventlet_Notifier(wm)
                wm.add_watch(self.watch_dir, mask,
                             proc_fun=on_notified, rec=False)
                self.notifier.loop()
                LOG.debug("File event notifier [pyinotify] waiting")
            except Exception as e:
                LOG.error(e)
                wm.rm_watch(self.watch_dir)
