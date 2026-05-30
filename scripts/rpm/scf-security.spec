Name:           scf-security
Version:        0.0.1
Release:        1
Summary:        Secure Communication Framework
Summary(zh_CN): 数据传输安全防护框架（SCF）
License:        MulanPSL-2.0
URL:            https://atomgit.com/openeuler/scf-security.git
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  g++, make, libboundscheck, rapidjson-devel
BuildRequires:  gcc-c++ >= 8, cmake >= 3.14
BuildRequires:  openssl-devel

# Runtime Requires
Requires:  libboundscheck

%description
scf-security (Secure Communication Framework) provides secure communication
libraries for data transmission protection on openEuler.

# define sub-package
%package devel
Summary:        Development files for %{name}
Requires:       %{name} = %{version}-%{release}
%description    devel
scf-security (Secure Communication Framework) provides development
headers and libraries for building applications that use the SCF security framework.

%prep
%autosetup -n %{name}-%{version} -p2

%global build_dir       %{_builddir}/%{name}-%{version}/build
%global output_dir      %{_builddir}/%{name}-%{version}/output

%build
export CFLAGS="%{optflags}"
export CXXFLAGS="%{optflags}"

cmake -S . -B build \
    -DBUILD_TEST=Off \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DDOWNLOAD_DEPENDENCY=Off \
    -DBUILD_FUZZ=Off \
    -DCMAKE_INSTALL_PREFIX=%{output_dir}

cmake --build build -- -j%{?_smp_build_ncpus}

cmake --install build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_includedir}
mkdir -p %{buildroot}%{_libdir}
mkdir -p %{buildroot}%{_sysconfdir}/scf

# Library files
install -m 550 %{output_dir}/lib64/libscf.so        %{buildroot}%{_libdir}

# Executable files

# Header files
install -m 440 %{output_dir}/include/*.h           %{buildroot}%{_includedir}/

# Configuration files
install -pm 640 %{output_dir}/config/config_template.json   %{buildroot}%{_sysconfdir}/scf/config_template.json

find %{buildroot} -name "*.so" -exec chmod u+s {} \;
find %{buildroot} -name "*.so.*" -exec chmod u+s {} \;

%files
%dir %attr(750, root, root) %{_sysconfdir}/scf
%config(noreplace) %attr(640, root, root) %{_sysconfdir}/scf/config_template.json

%attr(440, root, root) %{_includedir}/scf.h
%attr(440, root, root) %{_includedir}/scf_def.h
%attr(440, root, root) %{_includedir}/scf_errno.h
%attr(440, root, root) %{_includedir}/scf_ssl.h
%attr(550, root, root) %{_libdir}/libscf.so

%files devel
%attr(440, root, root) %{_includedir}/scf.h
%attr(440, root, root) %{_includedir}/scf_def.h
%attr(440, root, root) %{_includedir}/scf_errno.h
%attr(440, root, root) %{_includedir}/scf_ssl.h

%post

%changelog
