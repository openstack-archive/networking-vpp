# networking-vpp
ML2 Mechanism driver and small control plane for OpenVPP forwarder

This is a Neutron mechanism driver to bring the advantages of OpenVPP to
OpenStack deployments.

It's been written to be as simple and readable as possible, which means it's
naive; the aim was not to write the most efficient mechanism driver ever from
right out of the gate, but to write something simple and understandable and
see how well it works and what needs to be changed.

As a general rule, I've implemented everything in the simplest way, for two
reasons: one is that I get to see it working faster, and the other is that it's
much easier to replace a simple system with a more complex one than it is
to change a complex one.  The current design will change, but the one that's there
at the moment is small and easy to read, even if it makes you pull faces
when you read it.

## Your questions answered

### How do I use it?

There's a devstack plugin.  You can add this plugin to your local.conf and see it working.
You'll want to get VPP and the VPP Python bindings set up on the host before you do that.
I haven't written up the instructions yet but they're coming.

To get the best performance, this will use vhostuser sockets to talk to VMs, which means you
need a modern version of your OS (CentOS 7 and Ubuntu 16.04 look good).  It also means that
you need to run your VMs with a special flavor that enables shared memory - basically, you
need to set up hugepages for your VMs, as that's the only supported way Nova does this
today.  Because you're using pinned shared memory you are going to find you can't
overcommit memory on the target machine.

I've tested this on Ubuntu 16.04 - which, note, is not directly supported by the devstack
team, though it WFM.  You will need to export FORCE=yes in yur environment before you
run devstack.  You'll also need to disable libvirt security for qemu, as libvirt doesn't
play well with vhostuser sockets in its default setup.  CentOS testing is ongoing.

### What overlays does it support?

Today, it supports VLANs.

### How does it work?

VPP has one physical interface nominated as the trunk network (in Neutron
terms, it supports one 'physical' network today, with a hardcoded name).  When
a network is needed on a host, we create a subinterface with the selected
VLAN (the typedriver chooses the VLAN, we don't do anything clever about that)
and then makes a new bridge domain in VPP and puts the VLAN into it.  Binding
a port involves putting the port into the same bridge domain.

### How does it implement binding?

There are a number of calls that a mechanism driver can implement.  The
precommit calls determine if a create, update or delete is acceptable and
stop it before it hits the database; they can also update additional
database tables.  The postcommit calls are where you should trigger
actions based on an update that's now been accepted and saved (you can't
back down at that point).  Additionally, there are some helper calls
to determine if this mechanism driver, in conjunction with the other
ones on the system, needs to do anything.

This mechanism driver takes two approaches.  It doesn't do
anything at all until Neutron needs to drop traffic on a compute host, so
the only thing it's really interested in is ports.  Making a network or a
subnet doesn't do anything at all, so there are no entry points for the
network and subnet routings.  And it mainly interests itself in the process
of binding: the bind calls determine if it has work to do, and the
port postcommit calls make sure that, when a binding takes, the VPP
forwarders in the system get appropriately programmed to put the traffic where
Nova expects it.

### How does it talk to VPP?

This uses the Python module Ole Troan added to VPP to interface with the
forwarder.  VPP has an admin channel, implemented as a couple of shared
memory queues, to exchange control messages with VPP.  The Python bindings
are a very thin layer between that shared memory system and a set of Python
APIs.

Note that VPP runs as root and so the shared memory buffers are protected
and need root credentials to access, so the agent also runs as root.  It
rather inelegantly coredumps if it doesn't have root privileges.

### What doesn't it support?

This list is much longer than what it does support at the moment.  For now,
assume it moves packets to where they need to go and not very much else.

### What are you doing next?

This driver is a good ML2 citizen, and so it should support the non-L2 features
that ML2 brings with it.  Right now, I'm working on integrating the DHCP,
metadata and L3 agents with it - this means 'binding' TAP devices when a
network port is requested for a feature.  Neutron doesn't give you many clues
that it needs a specific binding type, so that's not as easy as it might be;
but it's easy enough, and it means that we get a working system now and we can
use VPP's internal features to enhance these elements in the future.

### What else needs fixing?

There are a long list of items where you can help.  At the moment, the
reliability of the messaging is one area where there's a chunk of work to do
(see below); that aside, you could attempt to get VXLAN working, or you could
look at tidying up the VPP API in the OpenVPP codebase, or you could add a
working memory to the VPP agent (perhaps by adding user-data to the VPP API
so that the agent could annotate the ports with its own information).  It
could use multiple physical networks, requiring a physical network name:VPP port
mapping in the config on the compute nodes.

Firewalling and security groups are another big area where it's lacking.
If you're moving packets around fast and you're using secure components in
your VMs they don't matter so much (and this is quite common in NFV scenarios)
but to make this useful for everything the driver needs to implement basic
anti-spoof firewalling, security groups, and also the allowed-address-pair
and portsecurity extensions so that security can be turned down when the
application needs something different.  VPP has ACLs; the firewall
requirements can be turned into ACL programming calls to set all of this up.
If you do think of trying this, remember that when you change a security group
you might be changing the firewalling on lots of ports - on lots of servers -
all at the same time.

You're welcome to search the source code for TODO comments; when I've found
something I wanted to put off for later I've generally tried to mark that
in place.

### Why didn't you use the ML2 agent framework for this driver?

Neutron's agent framework is based on communicating via RabbitMQ.  This can
lead to issues of scale when there are more than a few compute hosts involved,
and RabbitMQ is not as robust as it could be, plus RabbitMQ is trying to be a
fully reliable messaging system - all of which work against a robust and
scalable SDN control system.

I didn't want to start down that path, so for the moment I've implemented a
simple REST framwework to serve as a placeholder for a better system.  That REST
framework is /not/ intended to be a permanent solution; for now, though, it gets
messages where they need to go when the system is running happily.  In the longer
term, it needs to address a few points:

 - Neutron servers can restart
 - There can be multiple Neutron-server processes (for redundancy and scale-out)
   and the system needs to know what to do when several copies are running
 - VPP agents and VPP processes can also restart, and they need to quickly
   remember what they're doing - ideally without leaking firewalled packets in
   the meantime - and realising that the work they were doing as they restarted
   may not have completed
 - when you're working with many many forwarders you need the backend to be
   asynchronous; all the REST calls to agents (or whatever replaces them)
   should be converted to something where you don't hold up all the rest of
   the work just while you wait for a reply.

There are a few examples of good design patterns in the Neutron community we
could follow.  In particular, the ODL driver understands how to remember
what to do and in what order in the face of failures on either end of the control
connection, even when using REST.  The basic agent framework shows how agents can
automatically reveal themselves to servers.  This is all work to do, but,
following the mantra of 'release early and often' this version is here for you to
use and experiment with and even to add those features yourself.

Per above, VPP's comms channel with control planes is privileged, and so is the
channel for making vhost-user connections (you need to know the credentials that
libvirt uses).  If it weren't for those two things, the agent doesn't need any
special system rights and could run as a normal user.  This could be fixed (by
getting VPP to drop the privs on the shared memory and by using e.g. a setgid
directory to talk to VPP, respectively).

### Why did you use a broadcast mechanism for getting the data to the forwarders?

Pure laziness.  It's the easiest thing to implement and since I'm actually on
single-host devstack for my testing there's actually no penalty for calling out
to each forwarder.

### Why do I have to list the agents on my compute nodes in config?

Auto-discovery is needed; it's just faster to get something out of the door without
it.
