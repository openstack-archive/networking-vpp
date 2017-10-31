#!/usr/bin/python

# Copyright (c) 2016 Cisco Systems, Inc.
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

# Convert a YAML config to a VPP one.  Combines multiple files.
# Some VPP outputs don't have set values (for which the YAML will contain a
# nil value).
# Does not fix quoting.  Probably should.
# This is intended to be paired, one day, with a config file reader, to
# make config file modification possible.

import copy
import sys
import yaml

data = {}


def overlay_struct(base, add):
    if isinstance(base, dict):
        out = copy.copy(base)
        for k, v in add.items():
            if k in out:
                out[k] = overlay_struct(out[k], v)
            else:
                out[k] = copy.copy(add[k])
    else:
        out = copy.copy(add)
    return out

for f in sys.argv[1:]:
    with open(f) as inf:
        overlay = yaml.load(inf)
        data = overlay_struct(data, overlay)

# This had better generate a dict...
for k, v in data.items():
    print("%s {" % k)
    for k2, v2 in v.items():
        if v2 is not None:
            print("    %s %s" % (k2, v2))
        else:
            print("    %s" % k2)
    print("}")
