%global libfprint_version 1.94.10
%global gm168_commit     %{?_commit:%{_commit}}%{?!_commit:HEAD}

Name:           libfprint-goodix-gm168
Version:        0.1.0
Release:        1%{?dist}
Summary:        libfprint with out-of-tree Goodix GM168SEC fingerprint driver
License:        LGPL-2.1-or-later
URL:            https://github.com/mrcook1e-ai/goodix-gm168

# Upstream libfprint tarball we rebuild against.  Track the exact tag
# the patch was authored against — bumping requires patch rebase.
Source0:        https://gitlab.freedesktop.org/libfprint/libfprint/-/archive/v%{libfprint_version}/libfprint-v%{libfprint_version}.tar.bz2
# This package's own checkout (driver sources + patch + udev rule).
# In COPR builds the srpm provides this as a vendored tarball.
Source1:        goodix-gm168-%{version}.tar.gz

BuildRequires:  meson >= 0.59
BuildRequires:  ninja-build
BuildRequires:  gcc
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gusb)
BuildRequires:  pkgconfig(openssl) >= 3.0
BuildRequires:  pkgconfig(cairo)
BuildRequires:  pkgconfig(pixman-1)
BuildRequires:  pkgconfig(libudev)
BuildRequires:  pkgconfig(gudev-1.0)
BuildRequires:  pkgconfig(gobject-introspection-1.0)
BuildRequires:  pkgconfig(nss)
BuildRequires:  systemd-rpm-macros
BuildRequires:  systemd-udev

Requires:       fprintd
Requires:       openssl-libs >= 3.0

# We ship a libfprint-2.so.2 that replaces the upstream one — fprintd
# will load ours because we install to %{_libdir} too.  Mark the conflict
# explicitly so dnf can't end up with both sets of .so files on disk.
Conflicts:      libfprint
Provides:       libfprint = %{libfprint_version}
Provides:       libfprint%{?_isa} = %{libfprint_version}

%description
This package replaces the system libfprint with a build that includes
an out-of-tree driver for the Goodix GM168SEC capacitive fingerprint
sensor (USB 27c6:589a), found in several Lenovo / HP / ASUS laptops
where the bundled libfprint reports "No driver found".

The driver speaks the sensor's native TLS-PSK protocol over USB and
hands decoded 80x64 fingerprint images to NBIS / fprintd unchanged.
PSK material is per-device and must be present at
/etc/goodix-gm168/psk.bin before the first activation — see
%{_docdir}/%{name}/INSTALL.md for the unseal procedure.

%prep
# Lay out: ./libfprint-v%{libfprint_version}/ + ./goodix-gm168-%{version}/
%setup -q -n libfprint-v%{libfprint_version}
%setup -q -T -D -a 1 -n libfprint-v%{libfprint_version}

# Move our driver sources into the libfprint tree and apply the patch
# that wires them into the build.  Same flow as scripts/build.sh.
mkdir -p libfprint/drivers/goodix_gm168
cp -a ../goodix-gm168-%{version}/src/* libfprint/drivers/goodix_gm168/
# Drop the standalone meson.build — the in-tree one is added by the patch.
rm -f libfprint/drivers/goodix_gm168/meson.build
%patch -p1 -P0 --fuzz=0 < ../goodix-gm168-%{version}/patches/libfprint-add-gm168.patch

%build
%meson \
    -Ddrivers=default \
    -Dudev_rules=disabled \
    -Dgtk-examples=false \
    -Ddoc=false \
    -Dintrospection=false \
    %{nil}
%meson_build

%install
%meson_install

# Driver-private state directory (PSK, sealed blob).
install -d -m 0755 %{buildroot}%{_sysconfdir}/goodix-gm168

# Udev rule — uaccess for VID:PID 27c6:589a.
install -D -m 0644 \
    ../goodix-gm168-%{version}/packaging/udev/70-goodix-gm168.rules \
    %{buildroot}%{_udevrulesdir}/70-goodix-gm168.rules

# Windows-side PSK unseal helper — ships with the docs so users can
# copy it to their Windows install.
install -D -m 0644 \
    ../goodix-gm168-%{version}/tools/windows/gm168_unseal.ps1 \
    %{buildroot}%{_docdir}/%{name}/tools/windows/gm168_unseal.ps1

# Top-level docs the user needs to read.
install -D -m 0644 ../goodix-gm168-%{version}/README.md   %{buildroot}%{_docdir}/%{name}/README.md
install -D -m 0644 ../goodix-gm168-%{version}/INSTALL.md  %{buildroot}%{_docdir}/%{name}/INSTALL.md
install -D -m 0644 ../goodix-gm168-%{version}/LICENSE     %{buildroot}%{_docdir}/%{name}/LICENSE

%post
# Reload udev to pick up the new rule.
%udev_rules_update
# fprintd loads libfprint at startup — restart so it picks up our build.
if systemctl is-active --quiet fprintd; then
    systemctl restart fprintd >/dev/null 2>&1 || :
fi

%postun
%udev_rules_update
if [ $1 -eq 0 ] && systemctl is-active --quiet fprintd; then
    systemctl restart fprintd >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc %{_docdir}/%{name}
%{_libdir}/libfprint-2.so.2*
%{_libdir}/pkgconfig/libfprint-2.pc
%{_includedir}/libfprint-2/
%{_udevrulesdir}/70-goodix-gm168.rules
%dir %{_sysconfdir}/goodix-gm168
%{_libexecdir}/installed-tests/libfprint-2/
%{_datadir}/installed-tests/libfprint-2/
%{_datadir}/metainfo/org.freedesktop.libfprint.metainfo.xml

%changelog
* Tue Jun 10 2026 mrcook1e <noreply@github.com> - 0.1.0-1
- Initial RPM packaging.
- Bundles libfprint %{libfprint_version} + out-of-tree goodix_gm168 driver.
- Ships uaccess udev rule for 27c6:589a.
- Ships gm168_unseal.ps1 helper for Windows-side PSK extraction.
