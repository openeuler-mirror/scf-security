# scf-security

## Introduction

Secure Communication Framework (SCF) provides the secure communication framework SDK library and configuration templates for TLS protocols and algorithm suites, certificate validity verification, hardware acceleration, and transmission I/O. This improves the security of TLS-based secure communication applications and provides references for developers.

## Software Architecture

![](./docs/images/scf_introduction_EN.png)

## Compilation and Installation

1. Compilation Environment Requirements

   - The openEuler kernel version in the compilation environment must be 6.6 or later.
   - TLS component OpenSSL 1.1.1, 3.0.9, or 3.0.12.
   - In addition, you need to install the following dependencies:

   ```shell
   sudo yum install -y rpm-build
   sudo yum install -y make
   sudo yum install -y cmake
   sudo yum install -y gcc
   sudo yum install -y gcc-c++
   sudo yum install -y libboundscheck
   ```

2. Compilation Guide

    Perform compilation using the preset script.

    ```shell
    sudo sh build.sh rpm 
    ```

3. Installation Guide

    Use the generated RPM package for installation.

    ```shell
    sudo rpm -ivh --nodeps package/rpm/*/scf-security-*.rpm 
    ```

## References

- [API Documentation](docs/en/api_documentation.md)
- [Code Sample](sample/sample.md)

## License Information

This project is released under Mulan PSL v2. For details, see [LICENSE](LICENSE).

## Contribution

1. Fork this repository.
2. Create a Feat_*xxx* branch.
3. Commit code.
4. Create a pull request (PR).

## Notes

Use the file naming pattern `README_xx.md` to indicate a supported language (for example, `README_EN.md`).
