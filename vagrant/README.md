Vagrant
=======

vagrant is to create openstack with vpp. It is verified to work in the env:
   Host: Ubuntu 16.04 64bit with 16G memory & 256G disk
   Vagrant: 1.8.1
   Virtualbox: 5.0.24

Vagrant Setup
-------------

sudo apt-get install -y vagrant virtualbox


Openstack Setup
--------------

vagrant up

Openstack Cleanup
-----------------

vagrant destroy -f
