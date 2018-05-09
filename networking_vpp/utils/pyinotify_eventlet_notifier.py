# Copyright 2014 Koert van der Veer
# Adapted from pyeventlet, which is MIT licensed
#
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

import errno
import logging
import os
import pyinotify
import select
import six

# From 0.20.0 above eventlet has removed the select.poll method, but pyinotify
# has a dependency on it. We don't actually use the poll object anyway (we
# can't since eventlet doesn't monkey patch it, it doesn't work, which is why
# 0.20+ deletes it), so we can fix it specifically to make the initialiser
# here happy.
# So we set select.poll to a dummy poll object to let the init method of
# pyinotify.Notifier complete.


class DummyPoll(object):
    def register(self, *args, **kwargs):
        pass

    def unregister(self, *args, **kwargs):
        pass

LOG = logging.getLogger(__name__)


class Notifier(pyinotify.Notifier):

    def __init__(self, watch_manager, default_proc_fun=None, read_freq=0,
                 threshold=0, timeout=None):
        # Monkeypatch select.poll temporarily
        select.poll = DummyPoll
        pyinotify.Notifier.__init__(self, watch_manager, default_proc_fun=None,
                                    read_freq=0, threshold=0, timeout=None)
        # Remove - no-one should be using poll, but leaving this would give
        # confusing behaviour
        delattr(select, 'poll')

        # We won't be using the pollobj
        self._pollobj.unregister(self._fd)
        self._pollobj = None

    def check_events(self, timeout=None):
        while True:
            try:
                # blocks up to 'timeout' milliseconds
                if timeout is None:
                    timeout = self._timeout
                ret = select.select([self._fd], [self._fd], [self._fd])
            except select.error as err:
                if six.PY2 and err[0] == errno.EINTR:
                    break
                elif six.PY3 and err.errno == errno.EINTR:
                    break  # interrupted, retry
                else:
                    raise
            else:
                break

        # only one fd is polled
        return bool(ret[0])

    def stop(self):
        # The original stop method unregistered the pollobj, but we've already
        # done that just after construction.
        os.close(self._fd)
