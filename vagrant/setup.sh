#!/usr/bin/env bash

set -e
HOME=`pwd`

sudo sysctl -w vm.nr_hugepages=2048

sudo apt-get update -y
sudo apt-get install -y git linux-source linux-headers-`uname -r` build-essential
sudo modprobe uio

git clone -b master https://gerrit.fd.io/r/vpp
cd vpp
make install-dep UNATTENDED=y
make build-release
make build
make build-vpp-api
make pkg-deb
cd build-root
sudo dpkg -i *.deb
cd ${HOME}/vpp/vpp-api/python/
sudo python setup.py install

sudo sed -e '/dpdk /a socket-mem 512' -i /etc/vpp/startup.conf
sudo service vpp restart


sudo apt-get install etcd -y
sudo service etcd start
sudo apt install python-pip -y
sudo pip install python-etcd

cd ${HOME}
git clone https://github.com/openstack-dev/devstack 
cp /vagrant/local.conf devstack
cd devstack
#git checkout stable/mitaka
./stack.sh
