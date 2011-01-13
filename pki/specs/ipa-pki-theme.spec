Name:             ipa-pki-theme
Version:          9.0.0
Release:          2%{?dist}
Summary:          Certificate System - IPA PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%if 0%{?rhel}
ExcludeArch:      ppc ppc64 s390 s390x
%endif

%global overview                                                       \
Several PKI packages require a "virtual" Theme component.  These       \
"virtual" Theme components are "Provided" by various Theme "flavors"   \
including "dogtag", "redhat", and "ipa".  Consequently,                \
all "dogtag", "redhat", and "ipa" Theme components MUST be             \
mutually exclusive!                                                    \
%{nil}

%description %{overview}


%package -n       ipa-pki-common-theme
Summary:          Certificate System - PKI Common Framework User Interface
Group:            System Environment/Base

Conflicts:        dogtag-pki-common-theme
Conflicts:        dogtag-pki-common-ui
Conflicts:        redhat-pki-common-theme
Conflicts:        redhat-pki-common-ui

Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

%description -n   ipa-pki-common-theme
This PKI Common Framework User Interface contains
NO textual or graphical user interface for the PKI Common Framework.

This package is used by the Certificate System utilized by IPA.

%{overview}


%package -n       ipa-pki-ca-theme
Summary:          Certificate System - Certificate Authority User Interface
Group:            System Environment/Base

Conflicts:        dogtag-pki-ca-theme
Conflicts:        dogtag-pki-ca-ui
Conflicts:        redhat-pki-ca-theme
Conflicts:        redhat-pki-ca-ui

Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

%description -n   ipa-pki-ca-theme
This Certificate Authority (CA) User Interface contains
NO textual or graphical user interface for the CA.

This package is used by the Certificate System utilized by IPA.

%{overview}


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DBUILD_IPA_PKI_THEME:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


%files -n ipa-pki-common-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/common-ui/


%files -n ipa-pki-ca-theme
%defattr(-,root,root,-)
%doc dogtag/ca-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/ca-ui/


%changelog
* Thu Jan 13 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-2
- Bugzilla Bug #668836 - Review Request: ipa-pki-theme
-   Modified overview to pertain more to these packages
-   Removed "Obsoletes:" lines (only pertinent to internal deployments)
-   Modified installation section to preserve timestamps
-   Removed sectional comments

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

