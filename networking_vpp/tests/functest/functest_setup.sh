#!/bin/bash

OG_DEVSTACK_CREDS=~/devstack/openrc
DEVSTACK_CREDS=~/devstack/openstack.creds
SCRIPT_DIR=$(pwd)
# prep credentials file
rm -rf $DEVSTACK_CREDS
. $OG_DEVSTACK_CREDS admin admin && env | grep OS_ >> $DEVSTACK_CREDS
sed -i -e 's|^|export |' ${DEVSTACK_CREDS}
CONTAINER_CREDS=/home/opnfv/functest/conf/openstack.creds
OPENSTACK_IP=$(ifconfig eth0 | grep 'inet ' | awk '{printf $2}')
# set up key for test run (this will overwrite the existing key)
KEYNAME=ml2test
KEYFILE=~/.ssh/$KEYNAME
echo -e 'y\n'|ssh-keygen -q -t rsa -N "" -f $KEYFILE > /dev/null
cat $KEYFILE.pub >> ~/.ssh/authorized_keys

# install docker
sudo tee /etc/yum.repos.d/docker.repo <<-'EOF' 
[dockerrepo]
name=Docker Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/7/
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF

sudo yum -y -q install docker-engine
sudo service docker start
sudo usermod -aG docker $(whoami)

# install functest container
# INSTALLER_IP will be pointed locally
# overcloudrc_path is to devstack's openrc

sudo docker run --name functest --privileged=true -ti -d -e NODE_NAME=ml2_test \
    -e "INSTALLER_IP=$OPENSTACK_IP" -e CI_DEBUG=true -e \
    INSTALLER_TYPE=devstack -e DEPLOY_SCENARIO=os-nosdn-fdio-noha \
    -v $DEVSTACK_CREDS:$CONTAINER_CREDS -v $KEYFILE:/root/.ssh/id_rsa \
    opnfv/functest /bin/bash

# prep functest env and run functest
sudo docker exec -it functest bash -c "env && . $CONTAINER_CREDS && env && functest env prepare && export BUILD_TAG=‘vppml2-daily-colorado’ && /home/opnfv/repos/functest/ci/run_tests.py -t healthcheck"
