# Undefine CMake in-source builds in order to be consistent with f33+
%undefine __cmake_in_source_build

%global _hardened_build 1
%global debug_package %{nil}


Name:           arptools
Version:        0.1.2
Release:        2%{?dist}
Summary:        arpwatch ARP packet monitor

License:        BSD
URL:            https://github.com/NSLS-II/arptools
Source0:        https://github.com/NSLS-II/arptools/archive/refs/tags/v%{version}.tar.gz

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
%autosetup

%build
%cmake -DCPPLINT_CHECK=0
%cmake_build

%install
%cmake_install

%post
%systemd_post arpwatch.service

%preun
%systemd_preun arpwatch.service

%postun
%systemd_postun_with_restart arpwatch.service

%files
%license LICENSE
%{_bindir}/arpwatch
%{_unitdir}/arpwatch.service

%changelog
* Thu Jul 22 2021 Stuart Campbell <scampbell@bnl.gov> 0.1.2-2
- Added systemd support

* Thu Jul 22 2021 Stuart Campbell <scampbell@bnl.gov> 0.1.2-1
- Bumped version to 0.1.2

* Wed Jul 21 2021 Stuart Campbell <scampbell@bnl.gov> 0.1-1
- Initial version of package
