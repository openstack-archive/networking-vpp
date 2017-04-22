
To activate TLS between ML2 vpp and etcd, you need to do the following:

=================================================================================
A/ etcd

Note: this is not a fully detailed set of information about how a cloud should be secured.  You
will want to read up on the subject and consider such things as certificate expiry and so on.
This is just enough to get you started.

This configures etcd with a server certificate that the client can verify.  It does not
configure a client certificate that the server can verify (this is also an option).  In general,
you should probably use this with RBAC in etcd, so that clients also require a password to
connect to etcd.

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

In a secure environment, you must set a passphrase on your CA certificate.  Name
it as you like - this identity will be visible in the CA.  You *do not* want this file to go
anywhere near your cloud servers if this is a production cloud, as it allows malicious people
to create fake certificates for your servers.

This creates a root CA certificate:

    pki/ca.crt

4/ For each server in the etcd cluster, create the server certificate and private key

    ./easyrsa --subject-alt-name DNS:<server-fqdn> build-server-full <server-name> nopass

This will require the passphrase for the root CA (this is the one you set a moment ago).


The following files are created:

    pki/private/<server-name>.key
    pki/issued/<server-name>.crt

The private key that is created identifies etcd on the server in question, and is unencrypted (so
that etcd can use it) - do not let this escape to unsecure locations.

5/ Configure etcd

5.1/ Copy the files

    pki/ca.crt
    pki/private/<server-name>.key
    pki/issued/<server-name>.crt

to the directory  /etc/ssl/etcd/.  Set their permissions (assuming, here, etcd runs in group
'etcd'):

    chown -R root /etc/ssl/etcd/
    chgrp -R etcd /etc/ssl/etcd/
    chmod -R g+r,g-w,o-rw /etc/ssl/etcd/
    chmod g+rx,o+rx /etc/ssl/etcd/
    chmod go+r /etc/ssl/etcd/ca.crt
    chmod go+r /etc/ssl/etcd/<server-name>.crt

5.2/ Add the arguments to etcd when it runs.  This varies a bit by distribution, so you may need to
riff around the following.

For RHEL or CentOS, edit the file /etc/etcd/etcd.conf and add environment settings there
explaining the certificates required:
In Ubuntu, you may need to so this in the systemd service file, /etc/systemd/system/etcd2.service,
adding the lines with an Environment="" wrapper.

The settings are:

ETCD_KEY_FILE=/etc/ssl/etcd/<server-name>.key
ETCD_CERT_FILE=/etc/ssl/etcd/<server-name>.crt
ETCD_TRUSTED_CA_FILE=/etc/ssl/etcd/ca.crt

ETCD_ADVERTISE_CLIENT_URLS=https://<server-name>:2379
ETCD_LISTEN_CLIENT_URLS=https://<server-name>:2379
ETCD_INITIAL_ADVERTISE_PEER_URLS=https://<server-name>:2380
ETCD_LISTEN_PEER_URLS=https://<server-name>:2380

ETCD_PEER_KEY_FILE=/etc/ssl/etcd/<server-name>.key
ETCD_PEER_CERT_FILE=/etc/ssl/etcd/<server-name>.crt
ETCD_PEER_TRUSTED_CA_FILE=/etc/ssl/etcd/ca.crt

ETCD_PEER_CLIENT_CERT_AUTH=true

5.3/ restart etcd

    systemctl daemon-reload # rereads the systemd unit file if we edited it
    systemctl restart etcd

At this point, there are two things to test.  Firstly, can you connect to etcd with the CLI
client using the security options required:

etcdctl --endpoints https://<server-name>:2379/ --ca-file /etc/ssl/etcd/ca.crt ls /networking-vpp

Secondly, has the cluster assembled (which will happen when you get all your etcd servers
doing security):

etcdctl --endpoints https://<server-name>:2379/ --ca-file /etc/ssl/etcd/ca.crt cluster-health


=================================================================================
B/ Configure networking-vpp to use certificates as it talks to etcd:

1/ Copy the ca.crt file in the folder /etc/ssl/etcd on all the servers running vpp-agent
and neutron-server.  This allows the processes to confirm etcd is trusted.

2/ Update the ml2 plugin configuration files

Add the following lines in the configuration file /etc/neutron/plugins/ml2/ml2_conf.ini

    [ml2_vpp]
    etcd_insecure_explicit_disable_https = False
    etcd_ca_cert = /etc/ssl/etcd/ca.crt
    etcd_host = <server-name>

(for the last one, it's important you use the hostname and not 127.0.0.1; and remember, this is
where etcd is running, which may not be the local host and may be a list of hosts).

This will force etcd communications to work over an https connection.

3/ Restart neutron-server and vpp-agent processes to get them to pick up the new configuration.
