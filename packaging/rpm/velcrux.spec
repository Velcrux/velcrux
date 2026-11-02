Name:           velcrux
Version:        0.1.0
Release:        1%{?dist}
Summary:        High-Throughput, Resumable, Verifiable Bulk Data Transfer over QUIC

License:        Apache-2.0 OR MIT
URL:            https://github.com/Velcrux/velcrux
Source0:        velcrux-%{version}.tar.gz

BuildRequires:  systemd-rpm-macros
Requires:       ca-certificates

%description
Velcrux is an open-source bulk data transfer system engineered for high
Bandwidth-Delay Product (BDP) environments over QUIC with TLS 1.3 mTLS,
FastCDC content-defined chunking, and whole-file BLAKE3 verification.

%prep
%setup -q

%build
# Pre-compiled binary packaging

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/velcrux
mkdir -p %{buildroot}%{_localstatedir}/lib/velcrux
mkdir -p %{buildroot}%{_localstatedir}/log/velcrux
mkdir -p %{buildroot}/data/velcrux

install -m 0755 velcrux %{buildroot}%{_bindir}/velcrux
install -m 0755 velcruxd %{buildroot}%{_bindir}/velcruxd
install -m 0644 packaging/systemd/velcruxd.service %{buildroot}%{_unitdir}/velcruxd.service
install -m 0644 packaging/systemd/velcrux.service %{buildroot}%{_unitdir}/velcrux.service
install -m 0640 packaging/etc/velcrux/server.toml %{buildroot}%{_sysconfdir}/velcrux/server.toml.example
install -m 0640 packaging/etc/velcrux/grants.toml %{buildroot}%{_sysconfdir}/velcrux/grants.toml.example

%pre
getent group velcrux >/dev/null || groupadd -r velcrux
getent passwd velcrux >/dev/null || \
    useradd -r -g velcrux -d %{_localstatedir}/lib/velcrux -s /sbin/nologin \
    -c "Velcrux transfer daemon" velcrux
exit 0

%post
%systemd_post velcruxd.service

%preun
%systemd_preun velcruxd.service

%postun
%systemd_postun_with_restart velcruxd.service

%files
%license LICENSE-APACHE LICENSE-MIT
%doc README.md
%{_bindir}/velcrux
%{_bindir}/velcruxd
%{_unitdir}/velcruxd.service
%{_unitdir}/velcrux.service
%dir %attr(0750, velcrux, velcrux) %{_sysconfdir}/velcrux
%config(noreplace) %{_sysconfdir}/velcrux/server.toml.example
%config(noreplace) %{_sysconfdir}/velcrux/grants.toml.example
%dir %attr(0750, velcrux, velcrux) %{_localstatedir}/lib/velcrux
%dir %attr(0750, velcrux, velcrux) %{_localstatedir}/log/velcrux
%dir %attr(0750, velcrux, velcrux) /data/velcrux

%changelog
* Mon Nov 02 2026 Velcrux Core Team <maintainers@velcrux.io> - 0.1.0-1
- Initial production release v0.1.0 of Velcrux and Velcruxd
