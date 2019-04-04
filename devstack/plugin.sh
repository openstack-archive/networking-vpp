# plugin - DevStack plugin.sh dispatch script for vpp

source $DEST/networking-vpp/devstack/functions

vpp_debug() {
    if [ ! -z "$VPP_DEVSTACK_DEBUG" ] ; then
       "$@" || true # a debug command failing is not a failure
    fi
}

# For debugging purposes, highlight vpp sections
vpp_debug tput setab 1

name=networking-vpp

# All machines using the VPP mechdriver and agent
function pre_install_networking_vpp {
    setup_host_env
}

function install_networking_vpp {
    cd "$MECH_VPP_DIR"
    echo "Installing networking-vpp"
    setup_develop "$MECH_VPP_DIR"
    if is_fedora && [[ $DISTRO == "rhel7" ]]; then
        # This enables repositories with a newer QEMU version in
        # VPP only works with relatively recent QEMU versions (>2.0 at least)
        install_package centos-release-qemu-ev
        install_package qemu-kvm-ev
        # This ensures that any previously installed older QEMU doesn't get
        # preferentially used even when the new one is in place
        is_package_installed qemu-system-x86 && uninstall_package qemu-system-x86 || true
    fi
}

function init_networking_vpp {
    # In test environments where the network topology is unknown or cannot
    # be modified, we use 'tap0' as a logical interface by default
    if ! [ -z "$MECH_VPP_PHYSNETLIST" ]; then
        uplink=$(echo $MECH_VPP_PHYSNETLIST | cut -d ':' -f 2)
        # checking specifically for tap0 to avoid problems in developer
        # test envs where other logical interfaces may be specified.
        if ! [[ `vppctl show interface` =~ "$uplink" ]] && [[ "$uplink" =~ 'tap0' ]]; then
            echo "tap0 not found in vppctl show interface"
            # by default, vpp will internally name the first tap device 'tap0'
            vppctl create tap host-if-name test
            vppctl set interface state tap0 up
        fi
    fi
}

function configure_networking_vpp {
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp physnets $MECH_VPP_PHYSNETLIST
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp etcd_host $ETCD_HOST
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp etcd_port $ETCD_PORT
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp etcd_user $ETCD_USER
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp etcd_pass $ETCD_PASS
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp enable_vpp_restart $ENABLE_VPP_RESTART
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp gpe_src_cidr $GPE_SRC_CIDR
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp gpe_locators $GPE_LOCATORS
    iniset /$Q_PLUGIN_CONF_FILE ml2_vpp l3_hosts $L3_HOSTS

    if [ ! -z "$ETCD_CA_CERT" ] ; then
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp etcd_ca_cert $ETCD_CA_CERT
    else
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp etcd_insecure_explicit_disable_https True
    fi

    if [ ! -z "$JWT_CA_CERT" ] ; then
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_signing  True
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_controller_name_pattern $JWT_CONTROLLER_NAME_PATTERN
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_ca_cert $JWT_CA_CERT
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_node_cert $JWT_NODE_CERT
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_node_private_key $JWT_NODE_PRIVATE_KEY
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_max_duration  $JWT_MAX_DURATION
    else
       iniset /$Q_PLUGIN_CONF_FILE ml2_vpp jwt_signing  False
    fi

}

function shut_networking_vpp_down {
    :
}


# The VPP control plane element (we don't at this point start VPP itself TODO)

agent_service_name=vpp-agent

function pre_install_vpp_agent {
    :
}

function install_vpp_agent {
    :
}

function init_vpp_agent {
    # The VPP startup file should specify that this user is authorised to access the
    # api segment, and if we're installing we fix that
    run_process $agent_service_name "$VPP_CP_BINARY --config-file /$Q_PLUGIN_CONF_FILE --config-file /$NEUTRON_CONF"
}

function configure_vpp_agent {
    :
}

function shut_vpp_agent_down {
    stop_process $agent_service_name
}



agent_do() {
    if is_service_enabled "$agent_service_name"; then
       "$@"
    fi
}

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    # Set up system services
    echo_summary "Configuring system services $name"
    pre_install_networking_vpp
    agent_do pre_install_vpp_agent

elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    # Perform installation of service source
    echo_summary "Installing $name"
    init_networking_vpp
    install_networking_vpp
    agent_do install_vpp_agent

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    # Configure after the other layer 1 and 2 services have been configured
    echo_summary "Configuring $name"
    configure_networking_vpp
    agent_do configure_vpp_agent
    # Early start of VPP agent so that its physnets are ready when Neutron
    # comes up
    agent_do init_vpp_agent

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo_summary "Initializing $name"
    init_networking_vpp

elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
    for flavor in $(openstack flavor list -c Name -f value); do
        echo "INFO: Configuring $flavor to use hugepage"
        nova flavor-key $flavor set hw:mem_page_size=large
    done
fi

if [[ "$1" == "unstack" ]]; then
    # Shut down services
    shut_networking_vpp_down
    agent_do shut_vpp_agent_down
fi

if [[ "$1" == "clean" ]]; then
    # Remove state and transient data
    # Remember clean.sh first calls unstack.sh
    # no-op
    :
fi
vpp_debug tput setab 9

function neutron_plugin_install_agent_packages {
    install_package bridge-utils
}

function neutron_plugin_configure_l3_agent {
    :
}

# We have opinions on the interface driver that should attach agents
function neutron_plugin_setup_interface_driver {
    local conf_file=$1
    iniset $conf_file DEFAULT interface_driver linuxbridge
}

# This tells devstack that no, we're not using OVS in our plugin.
function is_neutron_ovs_base_plugin {
    false
}
