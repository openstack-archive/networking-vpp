#!/usr/bin/env bash

# Many of neutron's repos suffer from the problem of depending on neutron,
# but it not existing on pypi. This ensures its installed into the test environment.
set -ex

ZUUL_CLONER=/usr/zuul-env/bin/zuul-cloner
NEUTRON_BRANCH=${NEUTRON_BRANCH:-${DEFAULT_NEUTRON_BRANCH:-master}}
UPPER_CONSTRAINTS_FILE=${UPPER_CONSTRAINTS_FILE:-unconstrained}

install_cmd="pip install"

if [ "$UPPER_CONSTRAINTS_FILE" != "unconstrained" ]; then
    install_cmd="$install_cmd -c$UPPER_CONSTRAINTS_FILE"
fi

if $(python -c "import neutron" 2> /dev/null); then
    echo "Neutron already installed."
elif [ -x $ZUUL_CLONER ]; then
    # Use zuul-cloner to clone openstack/neutron, this will ensure the Depends-On
    # references are retrieved from zuul and rebased into the repo, then installed.
    $ZUUL_CLONER --cache-dir /opt/git --branch $NEUTRON_BRANCH --workspace /tmp git://git.openstack.org openstack/neutron
    $install_cmd /tmp/openstack/neutron
else
    # Install neutron from git.openstack.org
    $install_cmd -e git+https://git.openstack.org/openstack/neutron@$NEUTRON_BRANCH#egg=neutron
fi

# Install the rest of the requirements as normal
$install_cmd -U $*

exit $?
