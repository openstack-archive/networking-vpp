#!/usr/bin/python
# Copyright (c) 2017 Cisco Systems, Inc.
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

import etcd
import re
import time

from oslo_serialization import jsonutils


def dump_result(w):
    print('%s [%s] %s %s(modified %s)' %
          (time.strftime("%H:%M:%S"),
           w.action or 'read-all', w.key,
           ('ttl = %s ' % str(w.ttl) if w.ttl is not None else ''),
           w.modifiedIndex))
    try:
        val = jsonutils.loads(w.value)
        out = jsonutils.dumps(val, indent=4)
        print(' > ', re.sub("\n", "\n >  ", out))
    except Exception:
        print(' > ', w.value)


def main():
    c = etcd.Client(host='localhost', port=2379)

    tick = 0
    while True:
        res = c.read('/', recursive=True, index=tick)
        for w in res.children:
            dump_result(w)
        tick = res.etcd_index + 1

        try:
            while True:
                w = c.watch('/', recursive=True, index=tick)
                dump_result(w)
                tick = w.modifiedIndex + 1
        except etcd.EtcdException:
            # out of history
            pass

if __name__ == '__main__':
    main()
