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


#workaroud numa issue in qemu
cd ${HOME}
git clone https://github.com/openstack/nova -b stable/newton
cd nova; patch -p1 < /vagrant/disable_numa.diff
git add nova/virt/libvirt/driver.py
git commit -m "disable numa"

cd ${HOME}
git clone https://github.com/openstack-dev/devstack
cp /vagrant/local.conf devstack
cd devstack
git checkout stable/newton
./stack.sh

source openrc admin
nova flavor-key m1.tiny set hw:mem_page_size=2048
neutron net-list | grep private  | cut -f2 -d'|' | xargs -I {} bash -c "nova boot --flavor 1 --image=cirros-0.3.4-x86_64-uec --nic net-id={} vm1"
