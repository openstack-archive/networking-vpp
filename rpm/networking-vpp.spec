%define name networking-vpp
%define version %(python setup.py --version)
%define release 1
%define _topdir %(pwd)/build/rpm
%define _builddir %(pwd)
%define _rpmdir %(pwd)/build/rpm

Summary: OpenStack Networking for VPP
Name: %{name}
Version: %{version}
Release: %{release}
License: Apache 2.0
Group: Development/Libraries
BuildArch: noarch
Requires: vpp
Vendor: OpenStack <openstack-dev@lists.openstack.org>
Packager: Feng Pan <fpan@redhat.com>
Url: http://www.openstack.org/

%description
ML2 Mechanism driver and small control plane for OpenVPP forwarder

%install
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
mkdir -p %{buildroot}/usr/lib/systemd/system
install rpm/networking-vpp-agent.service %{buildroot}/usr/lib/systemd/system

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
/usr/lib/systemd/system/networking-vpp-agent.service
