# scf-security

#### Description

#### Software Architecture
Software architecture description

#### Build and install

1. Build Environment Requirements

- OpenEuler Kernel version: >=6.6
- Openssl version: 1.1.1，3.0.9, 3.0.12
- You also need to install the following dependency packages:

```shell
sudo yum install -y rpm-build
sudo yum install -y make
sudo yum install -y cmake
sudo yum install -y gcc
sudo yum install -y gcc-c++
sudo yum install -y libboundscheck
```

2. Build Instructions

- You can compile using preset scripts directly

```shell
sudo sh build_rpm.sh 
```

3. Install Instructions

- Install using an RPM package generated from compilation

```shell
sudo rpm -ivh --nodeps /root/rpmbuild/RPMS/*/scf-security-*.rpm 
```

#### Contribution

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


#### Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
