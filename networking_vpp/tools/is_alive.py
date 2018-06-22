#!/usr/bin/env python

import click
import etcd
import logging
import sys
from urllib3.exceptions import TimeoutError as UrllibTimeoutError

from networking_vpp import constants
from networking_vpp import etcdutils

@click.command(help="""Keep running while the VPP agent continues to heartbeat

Returns 0 (success) when the agent dies.
Returns 1 (error) if the agent is not alive when it starts.
""")
@click.option('--etcd-host', default="127.0.0.1",
    help="Etcd host IP address(es) to connect etcd client."
        "It takes two formats: single IP/host or a multiple "
        "hosts list with this format: 'IP:Port,IP:Port'. "
        "e.g: 192.168.1.1:2379,192.168.1.2:2379.  If port "
        "is absent, etcd_port is used.")
@click.option('--etcd-port', type=int, default=4001,
    help="Etcd port to connect the etcd client.  This can "
        "be overridden on a per-host basis if the multiple "
        "host form of etcd_host is used.")
@click.option('--etcd-user', default=None,
    help="Username for etcd authentication")
@click.option('--etcd-pass', default=None,
    help="Password for etcd authentication")
@click.option('--etcd-ca-cert', default=None,
    help="etcd CA certificate file path")
@click.option('--disable-https/--enable-https', is_flag=True, default=False,
    help="Use http without TLS to access etcd")
@click.argument('host', required=True)
def cli(etcd_host, etcd_port, etcd_user, etcd_pass,
    etcd_ca_cert, disable_https, host):

    factory = etcdutils.EtcdClientFactory(etcd_host, etcd_port,
        etcd_user, etcd_pass,
        etcd_ca_cert, disable_https)

    client = factory.client()

    key = constants.LEADIN + '/state/%s/alive' % host
    try:
        rv = client.get(key)
    except etcd.EtcdKeyNotFound:
        # If the key exists now, it's alive.  If not, then we have an
        # answer.
        click.echo('Host is not alive')
        sys.exit(1)


    # Continue to look for death, which will come when the key
    # goes away.
    while True:
        try:
            rv = client.watch(key, index=rv.etcd_index+1)
        except (etcd.EtcdWatchTimedOut, UrllibTimeoutError):
            # repeat at current index
            continue

        print rv

        if rv.action in ('expire', 'delete'):
            break

    sys.exit(0)




if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)

    cli()
