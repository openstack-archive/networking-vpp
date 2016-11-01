==============
networking-vpp
==============

ML2 Mechanism driver and small control plane for `OpenVPP forwarder`_

This is a Neutron mechanism driver to bring the advantages of OpenVPP to
OpenStack deployments.

It's been written to be as simple and readable as possible while offering
either full Neutron functionality or a simple roadmap to it.
While the driver is not perfect, we're aiming for

 - robustness in the face of failures (of one of several Neutron servers, of
   agents, of the etcd nodes in the cluster gluing them together)
 - simplicity
 - testability - having failure cases covered is no good if you don't have
   a means to test the code that protects you from them

As a general rule, everything is implemented in the simplest way,
for two reasons: one is that we get to see it working faster, and
the other is that it's much easier to replace a simple system with
a more complex one than it is to change a complex one.  The current
design will change, but the one that's there at the moment is small
and easy to read, even if it makes you pull faces when you read it.

Your questions answered
~~~~~~~~~~~~~~~~~~~~~~~

How do I use it?
----------------

There's a devstack plugin.  You can add this plugin to your local.conf
and see it working. You'll want to get VPP and the VPP Python bindings
set up on the host before you do that. Follow the steps in the How to
install section below for more details.

To get the best performance, this will use vhostuser sockets to talk to
VMs, which means you need a modern version of your OS (CentOS 7 and
Ubuntu 16.04 look good).  It also means that you need to run your VMs
with a special flavor that enables shared memory - basically, you
need to set up hugepages for your VMs, as that's the only supported
way Nova does this today.  Because you're using pinned shared memory
you are going to find you can't overcommit memory on the target
machine.

I've tested this on Ubuntu 16.04.  Others have tried it with CentOS
7.2. You may need to disable libvirt security for qemu, as libvirt
doesn't play well with vhostuser sockets in its default setup.
CentOS testing is ongoing. An initial CentOS 7 guide can be found
at `<CENTOS_7-guide.rst>`_

What overlays does it support?
------------------------------

Today, it supports VLANs and flat networks.

How does it work?
-----------------

VPP has physical interface nominated as the physical networks.  In
common with other Neutron drivers, each physical network can be
used as a flat or VLAN network, for either fully virtual tenant
networks or for provider networks.  When a VLAN-overlay network is
needed on a host, we create a subinterface with the selected VLAN
(the typedriver chooses the VLAN, we don't do anything clever about
that).  For all networks, the agent makes a new bridge domain in
VPP and puts the subinterface or host interface into it.  Binding
a port involves putting the port into the same bridge domain.

How does it implement binding?
------------------------------

This mechanism driver takes two approaches.  It doesn't do anything
at all until Neutron needs to drop traffic on a compute host, so
the only thing it's really interested in is ports.  Making a network
or a subnet doesn't do anything at all, so there are no entry points
for the network and subnet operations.  And it mainly interests
itself in the process of binding: the bind calls determine if it
has work to do, and the port postcommit calls make sure that, when
a binding takes, the VPP forwarders in the system get appropriately
programmed to put the traffic where Nova expects it.

There are a number of calls that a mechanism driver can implement.  The
precommit calls determine if a create, update or delete is acceptable and
stop it before it hits the database; they can also update additional
database tables.  The postcommit calls allow you to act once the
network change is permanently recorded.  These two calls, on ports,
are what we use.

In our case, we add a write to a journal table to the DB commit
from within the precommit.  This is not committed if the commit
fails for other reasons.

The postcommit calls are where you should trigger actions based on an
update that's now been accepted and saved (you can't back down at
that point) - but the tenant is still waiting for an answer, so
it's wise to be quick.  In our case, we kick a background thread
to push the journal log out, in order, to etcd.  etcd then contains
the desired state of each host agent, and the agents monitor etcd
for changes relevant to them and update their state.

To ensure binding is done correctly, we send Nova a notification
only when the agent has definitely created the structures in VPP
necessary for the port to work.  This is generally a good idea but
for vhost-user connections it's particularly important as QEMU goes
into a funny state if you start it with vhost-user sockets that
don't connect immediately.  This state tends to confuse libvirt and
nova; for that reason, we recommend you make VIF plugging failures
fatal with the relevant Nova config option, so that a VM is never
started with ports that haven't been properly bound and configured.

Additionally, there are some helper calls to determine if this
mechanism driver, in conjunction with the other ones on the system,
needs to do anything.  In some cases it may not be responsible for the
port at all.


How does it talk to VPP?
------------------------

This uses the Python module Ole Troan added to VPP to interface with the
forwarder.  VPP has an admin channel, implemented as a couple of shared
memory queues, to exchange control messages with VPP.  The Python bindings
are a very thin layer between that shared memory system and a set of Python
APIs.

Note that VPP runs as root and so the shared memory buffers are protected
and need root credentials to access, so the agent also runs as root.  It
rather inelegantly coredumps if it doesn't have root privileges.

What does it support?
------------------------

For now, assume it moves packets to where they need to go.  It also integrates
properly with ML2 L3, DHCP and Metadata functionality.

The main notable absence at this point is security groups.

What are you doing next?
------------------------

Security groups - this requires some additional functionality in VPP to work,
so we're currently waiting on that to be committed upstream.

We're considering how to add TAP-as-a-Service functionality
to the system so that you can prove, to your own satisfaction, that
the networking is operating correctly and your app is broken :)

What else needs fixing?
-----------------------

There are a long list of items where you can help.  If you want a slow
introduction to the code, read it!  It's not very big and it has comments and
everything.  Among those comments you'll find several TODO comments where we
have opinions about shortcuts that we took that need revisiting; if you want
a go at changing the code, those TODO statements are a really good place to
start.

That aside, you could attempt to get VXLAN working, or you could
look at tidying up the VPP API in the OpenVPP codebase, or you could add a
working memory to the VPP agent (perhaps by adding user-data to the VPP API
so that the agent could annotate the ports with its own information).

Firewalling and security groups are a big area where it's lacking.
If you're moving packets around fast and you're using secure components in
your VMs they don't matter so much (and this is quite common in NFV scenarios)
but to make this useful for everything the driver needs to implement basic
anti-spoof firewalling, security groups, and also the allowed-address-pair
and portsecurity extensions so that security can be turned down when the
application needs something different.  VPP has ACLs, but the VPP team are
looking at improving that functionality and we're currently waiting for the
next version of the code and a hopefully more convenient API to use.
If you do think of doing work on this, remember that when you change
a security group you might be changing the firewalling on lots of
ports - on lots of servers - all at the same time.

Per above, VPP's comms channel with control planes is privileged, and
so is the channel for making vhost-user connections (you need to know the
credentials that libvirt uses).  If it weren't for those two things,
the agent doesn't need any special system rights and could run as a
normal user.  This could be fixed (by getting VPP to drop the privs on
the shared memory and by using e.g. a setgid directory to talk
to VPP,respectively).

Why didn't you use the ML2 agent framework for this driver?
-----------------------------------------------------------

Neutron's agent framework is based on communicating via RabbitMQ.  This can
lead to issues of scale when there are more than a few compute hosts involved,
and RabbitMQ is not as robust as it could be, plus RabbitMQ is trying to be a
fully reliable messaging system - all of which work against a robust and
scalable SDN control system.

We didn't want to start down that path, so instead we've taken a different
approach, that of a 'desired state' database with change listeners.
etcd stores the data of how the network should be and the agents try to
achieve that (and also report their status back via etcd).  One nice feature
of this is that anyone can check how well the system is working - both sorts
of update can be watched in real time with the command

    etcdctl watch --recursive --forever /

The driver and agents should deal with disconnections across the
board, and the agents know that they must resync themselves with
the desired state when they completely lose track of what's happening.

How to Install?
---------------

1) CentOS(7.2) installation:
    After completing the below installation steps for CentOS, skip the step #2
    for Ubuntu installation and proceed from step #3

    a) Install the VPP(16.09) RPM using the following base_url for the repo:https://nexus.fd.io/content/repositories/fd.io.centos7/

       - sudo yum install vpp-16.09-release.x86_64

    b) Install the python-API(16.09) RPM package for VPP

       - sudo yum install https://github.com/vpp-dev/vpp/raw/1609-python/RPMs/vpp-python-api-16.09-release.x86_64.rpm

    c) Install a newer qemu version.
       The qemu package should be qemu-kvm-ev and the version should be
       2.3.0-31.el7.16.1 or later

       - sudo yum install -y centos-release-qemu-ev
       - sudo yum update -y qemu-kvm-ev
       - sudo yum remove -y qemu-system-x86 || true # remove in case you
         had the old version

    d) Install the etcd distributed key value store and start the service.
       For more information on etcd refer to: https://coreos.com/etcd/docs/latest

       - sudo yum -y install etcd
       - sudo systemctl enable etcd
       - sudo systemctl start etcd

    e) Install the python client for etcd

       - sudo pip install python-etcd


2) Ubuntu(16.04) installation:
    For Ubuntu, you will need to build VPP from source. For detailed
    instructions refer to:
    https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code

    a) Here are the quick VPP installation steps for Ubuntu:

       - git clone -b master https://gerrit.fd.io/r/vpp
       - cd vpp  #This is the $VPPROOT directory
       - make install-dep
       - make build-release
       - make build
       - make build-vpp-api
       - make pkg-deb    # make the debian pkgs
       - cd build-root
       - dpkg -i \*.deb  # install debian pkgs

    b) After installing VPP, install the python api package for VPP.
       This is required for the networking-vpp agent:

       - cd $VPPROOT/vpp-api/python/
       - sudo python setup.py install

    c) Install the etcd distributed key value store and start the service.
       For more information on etcd refer to: https://coreos.com/etcd/docs/latest

       - sudo apt-get update
       - sudo apt-get install etcd
       - sudo service etcd start

    d) Install the python client for etcd

       - sudo pip install python-etcd

  ::

    # Note: Etcd keys hang around from previous runs and confuses matters
    # Clean up the directory in etcd that we care about
    for f in $(etcdctl ls --recursive /networking-vpp); do etcdctl rm $f ; done 2>/dev/null
    for f in $(etcdctl ls --recursive /networking-vpp | sort -r); do etcdctl rmdir $f ; done  2>/dev/null

3) Enable HugePages
    The below command will use 4G of memory if you are using 2M
    HugePage size; you're likely to want at least 8G in your system
    for this to work happily. Nova doesn't respond to changes in hugepage
    capacity. So it is recommended to restack after both setting the
    number of huge pages and starting the VPP dataplane application
    (which consumes some huge pages).

    - sudo sysctl -w vm.nr_hugepages=2048

4) Start the VPP service
    VPP needs to be told what hugepages to use because we have to
    tell the same number to OpenStack

    - sudo sed -e '/dpdk /a socket-mem 512' -i /etc/vpp/startup.conf
    - sudo service vpp restart (or)
    - sudo systemctl enable vpp && sudo systemctl restart vpp
    
5) At this stage vpp will try to take over the interfaces on the server, depending on server setup this might require a reboot.
   after reboot , vpp configurations can be made using vppctl to recover/create IP connectivity as needed, look at:
   https://wiki.fd.io/view/VPP/Command-line_Interface_(CLI)_Guide 
   

6) Steps for devstack
    We have tested our code against the Mitaka release and as a
    result it is recommended to start with.

    - git clone https://git.openstack.org/openstack-dev/devstack
    - cd devstack
    - git checkout stable/mitaka

   Here's a sample local.conf with the settings we have tried. Ensure that
   you update the below to match your environment.

   ::

     [[local|localrc]]
     RABBIT_PASSWORD=password
     DATABASE_PASSWORD=password
     SERVICE_PASSWORD=password
     ADMIN_PASSWORD=password

     # Disable these services unless you need them
     disable_service cinder c-sch c-api c-vol
     disable_service tempest

     # Standard settings for enabling Neutron
     disable_service n-net
     enable_service q-svc q-dhcp q-l3 q-meta

     # The OVS/LB agent part of Neutron is not used
     disable_service q-agt

     #Enable networking-vpp plugin
     enable_plugin networking-vpp https://github.com/openstack/networking-vpp

     Q_PLUGIN=ml2
     Q_ML2_PLUGIN_MECHANISM_DRIVERS=vpp
     Q_ML2_PLUGIN_TYPE_DRIVERS=vlan,flat
     Q_ML2_TENANT_NETWORK_TYPE=vlan
     ML2_VLAN_RANGES=physnet1:100:200  # Set your correct Vlan ranges here
     # Map physical networks to uplink trunk interfaces on VPP
     # Find your uplink interfaces by using the command "sudo vppctl show int"
     # Use local0 as the upstream interface if you are doing a one host deployment
     # For a multi-node deployment make sure to use the correct uplink
     interface in the local.conf file on each compute node. Separate multiple
     interface mappings using a comma.
     MECH_VPP_PHYSNETLIST=physnet1:GigabitEthernet2/2/0
     # Etcd host to connect to
     ETCD_HOST=X.X.X.X
     # Etcd port to connect to
     ETCD_PORT=2379

   Stack it
     ./stack.sh   #You may have to use FORCE=yes ./stack.sh on Ubuntu 16.04

6) For VMs to run using vhostuser interfaces, they need hugepages
    Enable hugepage support by setting the nova flavor key

    - . ~/devstack/openrc admin admin
    - nova flavor-key <flavor_name> set hw:mem_page_size=2048

7) Now you have a working version of networking-vpp
    Congrats!!

8) Verification
     Use the below commands as a starting point to confirm if things are okay

   - sudo vppctl show bridge-domain # Examine the L2 bridge domains in VPP.
       A bridge-domain is created in VPP for each neutron L2 network.

   - sudo vppctl show bridge-domain <ID> detail # Examine the ports
       The above command lists the ports belonging to a bridge domain. You
       should see the VirtualEthernet interfaces of all the VMs and the tap
       interfaces for any q-dhcp and q-router processes belonging to that
       network.

   - sudo vppctl show vhost-user # Examine the status of vhost-user ports
       See if the memory regions have been mapped successfully


.. _OpenVPP forwarder: https://wiki.fd.io/view/VPP/What_is_VPP%3F
