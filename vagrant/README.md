Vagrant
=======

vagrant is to create openstack with vpp. It is verified to work in the env:
   Host: Ubuntu 16.04 64bit with 16G memory & 256G disk
   Vagrant: 1.8.6
   Virtualbox: 5.0.24

Vagrant Setup
-------------

sudo apt-get install -y virtualbox
wget --no-check-certificate https://releases.hashicorp.com/vagrant/1.8.6/vagrant_1.8.6_x86_64.deb
sudo dpkg -i vagrant_1.8.6_x86_64.deb

Openstack Setup
--------------

vagrant up

Openstack Cleanup
-----------------

vagrant destroy -f
