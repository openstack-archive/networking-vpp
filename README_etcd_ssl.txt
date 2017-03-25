
To activate TLS between ML2 vpp and etcd, you need to do the following:

=================================================================================
A/ ETCD
The certificates and private keys needed to use TLS with etcd can be generated as follows:


1/ Install open-vpn/easy-rsa:

    git clone https://github.com/OpenVPN/easy-rsa.git

2/  Configure easy-rsa:

    cd easy-rsa/easyrsa3
    cp vars.example vars

.. and edit the file 'vars' as needed, e.g.

    set_var EASYRSA_REQ_COUNTRY    "US"
    set_var EASYRSA_REQ_PROVINCE   "California"
    set_var EASYRSA_REQ_CITY       "San Francisco"
    set_var EASYRSA_REQ_EMAIL      "me@example.net"
    set_var EASYRSA_REQ_OU         "My Organizational Unit"

3/ Initialize the PKI and build the root CA

    ./easy-rsa init-pki
    ./easy-rsa build-ca

This creates a root CA certificate:

    pki/ca.crt

4/ For each server in the etcd cluster, create the server certificate and private key

    ./easyrsa build-server-full <server-name>

The following files are created:

    pki/private/<server-name>.key
    pki/issued/<server-name>.crt

5/ Configure etcd

5.1/ Copy the files

    pki/ca.crt
    pki/private/<server-name>.key
    pki/private/<server-name>.pem
    pki/issued/<server-name>.crt

to the dircetory  /etc/ssl/etcd/

5.2/ Edit the file /etc/systemd/system/etcd2.service, adding the lines:

    Environment="ETCD_CERT_FILE=/etc/ssl/etcd/<server-name>.pem"
    Environment="ETCD_KEY_FILE=/etc/ssl/etcd/<server-name>.key"
    Environment="ETCD_TRUSTED_CA_FILE=/etc/ssl/etcd/ca.crt
    Environment="ETCD_ADVERTISE_CLIENT_URLS=https://<server-name>:2379"
    Environment="ETCD_LISTEN_CLIENT_URLS=https://<server-name>:2379,http://<server-name>:4001"

5.3/ restart etcd

    systemctl restart etcd

=================================================================================
B/ Configure networking-vpp to use certificates as it talks to etcd:

1/ Copy the ca.crt file in the folder /etc/ssl/etcd on all the servers running vpp-agent
and neutron-server.  This allows the processes to confirm etcd is trusted.

2/ Update the ml2 plugin configuration files

Add the following lines in the configuration file /etc/neutron/plugins/ml2/ml2_conf.ini

    [ml2_vpp]
    etcd_insecure_explicit_disable_https = False
    etcd_ca_cert = /etc/ssl/etcd/ca.crt

This will force etcd communications to work over an https connection.

3/ Restart neutron-server and vpp-agent processes to get them to pick up the new configuration.