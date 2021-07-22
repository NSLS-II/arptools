# Undefine CMake in-source builds in order to be consistent with f33+
%undefine __cmake_in_source_build
%global _hardened_build 1
%global debug_package %{nil}


Name:           arptools
Version:        0.1
Release:        1%{?dist}
Summary:        arpwatch ARP packet monitor

License:        BSD
URL:            https://code.nsls2.bnl.gov/devops/arptools
Source0:        https://code.nsls2.bnl.gov/devops/arptools/-/archive/master/arptools-master.tar.gz

BuildRequires:  cmake
BuildRequires:  systemd-rpm-macros
BuildRequires:  libpcap-devel
BuildRequires:  libnet-devel
BuildRequires:  libconfig-devel
BuildRequires:  mariadb-connector-c-devel
Requires:       libpcap
Requires:       libnet


%description
arpwatch ARP packet monitor

%prep
%setup -q -n arptools-master


%build
%cmake -DCPPLINT_CHECK=0 
%cmake_build


%install
%cmake_install


%files
%license LICENSE
%{_bindir}/arpwatch
%{_unitdir}/arpwatch.service

%changelog
* Wed Jul 21 2021 Stuart Campbell <scampbell@bnl.gov> 
- Initial version of package
