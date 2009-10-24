Name:           pki-common
Version:        1.3.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Common Framework
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  dogtag-pki-common-ui
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  ldapjdk
BuildRequires:  osutil
BuildRequires:  pki-util
BuildRequires:  symkey
BuildRequires:  velocity
BuildRequires:  xalan-j2
Buildrequires:  xerces-j2

Requires:       java >= 1:1.6.0
Requires:       jss >= 4.2.6
Requires:       osutil
Requires:       pki-common-ui
Requires:       pki-java-tools
Requires:       pki-setup
Requires:       rhgb
Requires:       symkey
Requires:       tomcatjss
Requires:       %{_datadir}/java/ldapjdk.jar
Requires:       %{_datadir}/java/pki/cmsutil.jar
Requires:       %{_datadir}/java/pki/nsutil.jar
Requires:       %{_datadir}/java/velocity.jar
Requires:       %{_datadir}/java/xalan-j2.jar
Requires:       %{_datadir}/java/xerces-j2.jar
Requires:       velocity

Conflicts:      tomcat-native

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag PKI Common Framework is required by the following four
Dogtag PKI subsystems:

    the Dogtag Certificate Authority,
    the Dogtag Data Recovery Manager,
    the Dogtag Online Certificate Status Protocol Manager, and
    the Dogtag Token Key Service.

%package javadoc
Summary:    Dogtag Certificate System - PKI Common Framework Javadocs
Group:      Documentation

Requires:   pki-common = %{version}-%{release}

%description javadoc
Dogtag Certificate System - PKI Common Framework Javadocs

This documentation pertains exclusively to version %{version} of
the Dogtag PKI Common Framework.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="common" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_datadir}/java/pki
mv certsrv.jar certsrv-%{version}.jar
ln -s certsrv-%{version}.jar certsrv.jar
mv cms.jar cms-%{version}.jar
ln -s cms-%{version}.jar cms.jar
mv cmsbundle.jar cmsbundle-%{version}.jar
ln -s cmsbundle-%{version}.jar cmsbundle.jar
mv cmscore.jar cmscore-%{version}.jar
ln -s cmscore-%{version}.jar cmscore.jar
mkdir -p %{buildroot}%{_sharedstatedir}/tomcat5/common/lib
cd %{buildroot}%{_sharedstatedir}/tomcat5/common/lib
ln -s %{_datadir}/java/ldapjdk.jar ldapjdk.jar
ln -s %{_datadir}/java/pki/cmsutil.jar cmsutil.jar
ln -s %{_datadir}/java/pki/nsutil.jar nsutil.jar
ln -s %{_datadir}/java/velocity.jar velocity.jar
ln -s %{_datadir}/java/xalan-j2.jar xalan-j2.jar
ln -s %{_datadir}/java/xerces-j2.jar xerces-j2.jar

%clean
rm -rf %{buildroot}

%post
%{_datadir}/pki/setup/postinstall pki

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/java/pki
%{_datadir}/pki/*
%{_sharedstatedir}/tomcat5/common/lib/*

%files javadoc
%defattr(0644,root,root,0755)
%dir %{_javadocdir}/%{name}-%{version}
%{_javadocdir}/%{name}-%{version}/*

%changelog
* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
