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

from __future__ import absolute_import
import logging
import os
import six
import socket
import struct

from networking_vpp._i18n import _

LOG = logging.getLogger(__name__)


# Kernel API constants, format helpers
class RTMGRP(object):
    # Link-state message group
    LINK = 1


class IncompleteMsg(Exception):
    """unpack_nlmsg throws this if it comes up short of data"""
    pass


def unpack_nlmsg(data):
    """Unpack a netlink message

    Returns msg_len, msg_type, flags, seq, pid; the message body according
    to the header's length; and any leftover data.

    Accepts that data may not contain a complete message yet.
    """

    if len(data) < 16:
        # Not enough data for the header
        raise IncompleteMsg()

    msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", data[:16])

    if len(data) < msg_len:
        # Not enough data for the whole message
        raise IncompleteMsg()

    return msg_type, flags, seq, pid, data[16:msg_len], data[msg_len:]


def pack_linkrequest(req_type, flags, body=b''):
    """Pack a netlink message requesting a list of links

    Returns the binary blob to send.
    """
    req = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0)
    hdr_pack = "=LHHLL"
    total_len = struct.calcsize(hdr_pack) + len(req) + len(body)

    hdr = struct.pack("=LHHLL", total_len, req_type, flags, 1, os.getpid())

    return hdr + req + body


def unpack_linkmsg(data):
    """For *LINK RTNETLINK messages, unpack the body

    Discards a number of uninteresting parts.

    Returns if type, flags and remainder of message
    """
    if_family, _, if_type, index, flags, change = struct.unpack("=BBHiII",
                                                                data[:16])
    # family == AF_UNSPEC.  _ is a pad word. change is not used by kernels yet.
    return if_type, flags, data[16:]


class NLM_F(object):
    """NLM flag values from Linux kernel (NLM_F_*)"""
    REQUEST = 1             # It is request message.
    MULTI = 2               # Multipart message, terminated by NLMSG_DONE
    ACK = 4                 # Reply with ack, with zero or error code
    ECHO = 8                # Echo this request
    DUMP_INTR = 16          # Dump was inconsistent due to sequence change
    DUMP_FILTERED = 32      # Dump was filtered as requested

    # Modifiers to GET request
    ROOT = 0x100            # specify tree root
    MATCH = 0x200           # return all matching
    ATOMIC = 0x400          # atomic GET
    DUMP = (ROOT | MATCH)

    # Modifiers to NEW request
    REPLACE = 0x100         # Override existing
    EXCL = 0x200            # Do not touch, if it exists
    CREATE = 0x400          # Create, if it does not exist
    APPEND = 0x800          # Add to end of list


def unpack_attr(data):
    """Unpack an RTA in a netlink message

    RTAs are TLV attributes with body format dependent on attr.

    Returns attr type, value, rest of message.
    """
    rta_len, rta_type = struct.unpack("=HH", data[:4])
    rta_len = rta_len - 4  # the header
    data = data[4:]

    attr_body = data[:rta_len]
    data = data[rta_len:]

    return rta_type, attr_body, data


# Message types we care about
class NLMSG(object):
    """Message types from Linux kernel.

    See net/if.h.
    Far from an exhaustive list.
    """
    NOOP = 1
    ERROR = 2
    DONE = 3
    RTM_NEWLINK = 16
    RTM_DELLINK = 17
    RTM_GETLINK = 18
    RTM_SETLINK = 19


# Interface flags (from net/if.h):
class IFF_FLAGS(object):
    """IFF flag values from Linux kernel.

    See net/if.h.
    """
    IFF_UP = 0x1               # Interface is up.
    IFF_BROADCAST = 0x2        # Broadcast address valid.
    IFF_DEBUG = 0x4            # Turn on debugging.
    IFF_LOOPBACK = 0x8         # Is a loopback net.
    IFF_POINTOPOINT = 0x10     # Interface is point-to-point link.
    IFF_NOTRAILERS = 0x20      # Avoid use of trailers.
    IFF_RUNNING = 0x40         # Resources allocated.
    IFF_NOARP = 0x80           # No address resolution protocol.
    IFF_PROMISC = 0x100        # Receive all packets.

    IFF_ALLMULTI = 0x200       # Receive all multicast packets.

    IFF_MASTER = 0x400         # Master of a load balancer.
    IFF_SLAVE = 0x800          # Slave of a load balancer.

    IFF_MULTICAST = 0x1000     # Supports multicast.

    IFF_PORTSEL = 0x2000       # Can set media type.
    IFF_AUTOMEDIA = 0x4000     # Auto media select active.
    IFF_DYNAMIC = 0x8000        # Dialup device with changing addresses.


class IFLA(object):
    """Attribute type enum from Linux kernel.

    See net/if.h.
    Not complete.
    """
    IFNAME = 3


class DeviceMonitor(object):
    """Watch for new network devices and signal.

    Calls back if a device appears or disappears from the kernel.
    TAP devices commonly do this a lot.

    Will return 'add's for all devices on startup.
    """

    def __init__(self):
        self.devices = set()
        # List of callback functions to be executed on device add/delete events
        self.add_cb = []
        self.del_cb = []

    def _dev_add(self, dev_name):
        """Run all registered add callbacks.

        Run when a device is added.
        """
        if dev_name not in self.devices:
            self.devices.add(dev_name)
            for f in self.add_cb:
                f(dev_name)

    def _dev_del(self, dev_name):
        """Run all registered delete callbacks.

        Run when a device is deleted.
        """
        if dev_name in self.devices:
            self.devices.discard(dev_name)
            for f in self.del_cb:
                f(dev_name)

    def on_add(self, func):
        """Add a function to be called when new i/f is found."""
        self.add_cb.append(func)

    def on_del(self, func):
        """Add a function to be called when i/f goes away."""
        self.del_cb.append(func)

    def run(self):
        """Run indefinitely, calling callbacks when interfaces change

        This uses just the socket API and so should be friendly with
        eventlet.  Ensure your callbacks are eventlet-safe if you do
        this.
        """
        def messages(s):
            """Iterator providing all messages in a netlink stream"""
            while True:
                incoming = s.recv(65535)

                # Work through the messages in this packet
                while len(incoming) > 0:
                    try:
                        msg_type, flags, seq, pid, data, incoming = \
                            unpack_nlmsg(incoming)
                        yield msg_type, flags, seq, pid, data
                    except IncompleteMsg:
                        # We seem to have half a message.
                        # This shouldn't happen, so we go with
                        # discarding it and moving on to the next
                        # packet
                        LOG.warning('Received incomplete message from'
                                    ' NETLINK, dropping')

        while True:
            s = None
            try:
                # Create the netlink socket and bind to RTMGRP.LINK messages
                s = socket.socket(socket.AF_NETLINK,
                                  socket.SOCK_RAW,
                                  socket.NETLINK_ROUTE)
                s.bind((os.getpid(), RTMGRP.LINK))

                # Re-issue a 'tell me all your interfaces' request, allowing
                # us to resync with either initial state or missed change
                # messages.

                get_links = pack_linkrequest(NLMSG.RTM_GETLINK,
                                             NLM_F.REQUEST | NLM_F.DUMP)
                s.send(get_links)
                resync_links = set()

                for msg_type, flags, seq, pid, data in messages(s):

                    if msg_type == NLMSG.NOOP:
                        # Meh.
                        continue
                    elif msg_type == NLMSG.ERROR:
                        # Force a netlink reset.
                        raise Exception(_("Error received on netlink socket"))
                    elif msg_type == NLMSG.DONE:
                        # We were presumably resyncing, and now we have
                        # everything.

                        # Having processed all of the incoming message,
                        # consider whether we have either new or dead links:
                        LOG.debug('getlink: saw links %s',
                                  ', '.join(resync_links))
                        new_links = resync_links - self.devices
                        dead_links = self.devices - resync_links

                        for f in new_links:
                            self._dev_add(f)
                        for f in dead_links:
                            self._dev_del(f)

                        resync_links = None
                        continue

                    # We're interested in tap devices appearing and
                    # disappearing. Anything else can pass us by.
                    if msg_type not in (NLMSG.RTM_GETLINK,
                                        NLMSG.RTM_NEWLINK,
                                        NLMSG.RTM_DELLINK):
                        continue

                    if_type, flags, data = unpack_linkmsg(data)

                    link_name = None
                    while len(data) > 0:
                        # This check comes from RTA_OK, and terminates a string
                        # of routing attributes.

                        attr_type, attr_body, data = unpack_attr(data)

                        # Hoorah, a link is up!
                        if attr_type == IFLA.IFNAME:
                            # As returned, includes a C-style \0
                            link_name = attr_body[:-1]
                            # py3 note:
                            # link_name is a bytes object so explicitly convert
                            # to string in case of py3 otherwise we get an
                            # exception.
                            if six.PY3:
                                link_name = link_name.decode('utf-8')
                            break

                    if link_name is None:
                        raise Exception(_("Add-link message without if name"))

                    if msg_type == NLMSG.RTM_NEWLINK:
                        if resync_links is not None:
                            # We're actually in a dump
                            resync_links.add(link_name)
                        else:
                            self._dev_add(link_name)
                    else:
                        self._dev_del(link_name)

            except KeyboardInterrupt:
                raise
            except Exception:
                LOG.exception("Unexpected exception in device watching"
                              " thread - resetting")
            finally:
                if s is not None:
                    s.close()
                    s = None
