#!/bin/bash

#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Secure Communication Framework is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#

###
### build.sh --- build project
###
### Usage:
###     build.sh <target> [-D] [-C] [-t <target>]
###
### Options:
###     <target>        Build target used by Make
###     -h | --help     Show help message
###     -D | --debug    Build debug version
###     -C | --coverage Generate coverage report files
###     -t | --target   Specifying build target, default is `all`
###                     Supported targets:
###                         `all`              build all target in source code
###                         `test`             build all tests in test/ directory
###                         `cicd_default`     build mode for cicd output only
###                         `cicd_coverage`    build mode for cicd coverage only
###                         `rpm`              build mode for rpm package only

# 函数内命令（后台命令）失败时，立即退出函数
set -o errtrace
# 脚本内命令（前台命令）失败时，立即退出脚本
set -o errexit

build_target='all'
build_type='Release'
enable_coverage='Off'
enable_test='Off'
download_dependency='Off' # 是否自动下载依赖，否则请手动下载依赖至 project_root/external 文件夹
enable_fuzz='Off'

CPU_NUM=$(grep -w processor /proc/cpuinfo|wc -l)

# 获取项目根目录（目前为构建脚本所在目录）
PROJECT_ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# rpm包信息
SPEC_FILE="$PROJECT_ROOT_DIR/scripts/rpm/scf-security.spec"
RPMBUILD_ROOT="$PROJECT_ROOT_DIR/build/rpmbuild"
# Extract Name and Version from spec
RPM_PKG_NAME=$(awk -F: '/^Name:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' "$SPEC_FILE")
RPM_PKG_VERSION=$(awk -F: '/^Version:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' "$SPEC_FILE")
RPMBUILD_SRC="$RPMBUILD_ROOT/SOURCES"
RPM_SRC_TARBALL="$RPMBUILD_SRC/${RPM_PKG_NAME}-${RPM_PKG_VERSION}.tar.gz"


OUTPUT_DIR=${PROJECT_ROOT_DIR}/output

# 脚本出错时捕获错误，并执行 trap_error 处理错误
trap 'trap_error "${LINENO}" "${FUNCNAME}" "${BASH_LINENO}"' ERR
# 脚本退出时，恢复到脚本的执行目录
trap 'cd "${PROJECT_ROOT_DIR}"' EXIT

FAILURE='[\033[1;31mFAILED\033[0;39m]'

# 日志打印辅助函数
function log_info() {
    if [ $# -lt 1 ]; then
        return
    fi
    echo "$(date +"%F %T") [INFO] $*" >>"$LOG_FILE"
    echo "$(date +"%F %T") [INFO] $*"
}

# 脚本错误处理
function trap_error() {
    local err=$?
    local line=$1 # LINENO
    [ "$2" != "" ] && local func_stack=$2 # func name
    [ "$3" != "" ] && local line_call_func=$3 # line where func was called
    echo "<---"
    echo "ERROR: line $line - command exited with status: $err"
    if [ "$func_stack" != "" ]; then
        echo -n "   ... Error at function ${func_stack[0]}() "
        if [ "$line_call_func" != "" ]; then
            echo -n "called at line $3"
        fi
        echo
    fi
    echo "--->"
}

function echo_failure() {
    echo -e "SCF project : $FAILURE"
}

function build_default() {
    cmake ..\
        -DCMAKE_BUILD_TYPE=${build_type}\
        -DBUILD_TEST=${enable_test}\
        -DENABLE_COVERAGE=${enable_coverage}\
        -DDOWNLOAD_DEPENDENCY=${download_dependency}\
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR}/scf\
        -DBUILD_FUZZ=${enable_fuzz}

    make -j${CPU_NUM}
    make install
    chmod 400 ${OUTPUT_DIR}/scf/lib64/libscf.so
    mkdir -p ${OUTPUT_DIR}/scf/config
    find ${OUTPUT_DIR}/scf/lib64/ -type f -name "lib*.so*" -exec chmod u+w {} +
    find ${OUTPUT_DIR}/scf/lib64/ -type f -name "lib*.so*" -exec strip {} +
    find ${OUTPUT_DIR}/scf/lib64/ -type f -name "lib*.so*" -exec chmod u-w {} +
}

function build_cicd_default() {
    cmake ..\
        -DCMAKE_BUILD_TYPE=Release\
        -DBUILD_TEST=Off\
        -DENABLE_COVERAGE=Off\
        -DDOWNLOAD_DEPENDENCY=Off\
        -DBUILD_FUZZ=Off\
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR}/scf

    make -j${CPU_NUM}
    make install
    chmod 400 ${OUTPUT_DIR}/scf/lib64/libscf.so
    mkdir -p ${OUTPUT_DIR}/scf/config
    find ${OUTPUT_DIR}/scf/lib64/ -type f -name "lib*.so*" -exec chmod u+w {} +
    find ${OUTPUT_DIR}/scf/lib64/ -type f -name "lib*.so*" -exec strip {} +
    find ${OUTPUT_DIR}/scf/lib64/ -type f -name "lib*.so*" -exec chmod u-w {} +
}

function packaging_src() {
    echo "==> Packaging source into: $RPM_SRC_TARBALL"
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    STAGE="$TMPDIR/${RPM_PKG_NAME}-${RPM_PKG_VERSION}"
    mkdir -p "$STAGE"
    rsync -a \
      --exclude '.git' \
      --exclude '.idea' \
      --exclude 'build' \
      --exclude 'external' \
      --exclude 'output' \
      --exclude 'package' \
      --exclude '*.o' \
      --exclude '*.a' \
      --exclude '*.so' \
      --exclude '*.so.*' \
      --exclude '*.swp' \
      --exclude '*~' \
      "$PROJECT_ROOT_DIR"/ "$STAGE"/
    tar -C "$TMPDIR" -czf "$RPM_SRC_TARBALL" "${RPM_PKG_NAME}-${RPM_PKG_VERSION}"
    rm -rf "$TMPDIR"
    trap - EXIT
}

function generate_checksum() {
    echo "==> Generating checksums"
    MANIFEST="$RPMBUILD_SRC/${RPM_PKG_NAME}-${RPM_PKG_VERSION}-sources.SHA256"
    {
      sha256sum "$RPM_SRC_TARBALL" || true
    } > "$MANIFEST"
}

function build_rpm() {
    rm -rf "${RPMBUILD_ROOT}"
    rm -rf "$PROJECT_ROOT_DIR/package"
    if [[ ! -f "$SPEC_FILE" ]]; then
      echo "ERROR: Spec file not found: $SPEC_FILE" >&2
      exit 1
    fi
    mkdir -p "$RPMBUILD_SRC"
    packaging_src
    generate_checksum
    echo "==> Preparing rpmbuild tree"
    mkdir -p "$RPMBUILD_ROOT"/{SPECS,BUILD,BUILDROOT}
    cp -f "$SPEC_FILE" "$RPMBUILD_ROOT/SPECS/"
    echo "==> Running rpmbuild"
    rpmbuild -ba "$SPEC_FILE" \
      --define "_sourcedir $RPMBUILD_SRC" \
      --define "_specdir $PROJECT_ROOT_DIR/rpm" \
      --define "_srcrpmdir $PROJECT_ROOT_DIR/package/srpm" \
      --define "_rpmdir $PROJECT_ROOT_DIR/package/rpm" \
      --define "_builddir $RPMBUILD_ROOT/BUILD" \
      --define "_buildrootdir $RPMBUILD_ROOT/BUILDROOT"

    echo "All done."
    echo "  - Source0: $RPM_SRC_TARBALL"
    echo "  - Checksums: $MANIFEST"
    echo "  - RPMs in:  $PROJECT_ROOT_DIR/package/rpm"
    echo "  - SRPM in:  $PROJECT_ROOT_DIR/package/srpm"
}

function build_cicd_coverage() {
    cmake ..\
        -DCMAKE_BUILD_TYPE=Release\
        -DBUILD_TEST=On\
        -DENABLE_COVERAGE=On\
        -DDOWNLOAD_DEPENDENCY=Off\
        -DBUILD_FUZZ=Off\
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR}/scf

    make -j${CPU_NUM}
    make install
    chmod 400 ${OUTPUT_DIR}/scf/lib64/libscf.so
    ctest --output-on-failure
    make coverage
}

function  run_test() {
    if [[ "${enable_test}" == "On" ]]; then
      ctest --output-on-failure
    fi
    if [[ "${enable_test}" == "On" ]]; then
      make coverage
    fi
}

# 执行 CMake 构建
function build_cmake() {

    if [[ $enable_clean == 'ON' ]]; then
        clean $build_target
    fi

    log_info "***** start build_cmake *****"

    pushd build
    log_info "building target ${build_target}."
    if [[ $build_target == 'all' ]]; then
        build_default
    fi

    if [[ "${build_target}" == 'test' ]]; then
            enable_test='On' # enable test
            build_default
            run_test
    fi

    if [[ $build_target == 'cicd_default' ]]; then
        enable_test='ON'
        build_cicd_default
    fi

    if [[ $build_target == 'rpm' ]]; then
        enable_test='ON'
        build_rpm
    fi

    if [[ $build_target == 'cicd_coverage' ]]; then
        enable_test='ON'
        build_cicd_coverage
    fi

    if [[ "${build_target}" == fuzz ]]; then
      build_type="Debug"
      enable_test="On"
      enable_coverage="Off"
      download_dependency="Off"
      enable_fuzz="On"
      build_default
    fi

    local ret=$?
    popd

    if [ $ret -ne 0 ]; then
        log_info "build_cmake failed"
        echo_failure
        exit 1
    fi
}

# 解析 help 信息并打印，help 信息放在文件头
# 注意：脚本内其他地方不要以 ### 开头进行注释
function help() {
    sed -rn 's/^### ?//;T;p;' "$0"
}

# 脚本参数解析
function parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        -h | --help)
            help
            exit
            ;;
        -D | --debug)
            build_type='Debug'
            shift
            ;;
        -t | --target)
            if [[ $# -gt 1 && "$2" != "-"* ]]; then
                build_target="$2"
                shift 2
            else
                log_info "Error: Argument required after -t|--target."
                exit 1
            fi
            ;;
        -C | --coverage)
            enable_coverage='ON'
            shift
            ;;
        -c | --clean)
            clean   # 清理构建目录
            shift
            ;;
        *)
            [ "$1" != "" ] &&build_target="$1"
            shift
            ;;
        esac
    done
}

function clean() {
    local target_dirs=()
    case $1 in
        "3rdparty")
            target_dirs+=("${PROJECT_ROOT_DIR}/deps")
            ;;
        "package")
            target_dirs+=("${PROJECT_ROOT_DIR}/build")
            target_dirs+=("${PROJECT_ROOT_DIR}/output")
            ;;
        *)
            target_dirs+=("${PROJECT_ROOT_DIR}/build")
            ;;
    esac

    for target_dir in "${target_dirs[@]}"; do
        if [ ! -d "$target_dir" ]; then
            echo "Warning: Directory '$target_dir' does not exist."
        else
            rm -rf "$target_dir"
            echo "Directory '$target_dir' has been cleaned."
        fi
    done

    if [[ ! -d ${PROJECT_ROOT_DIR}/build ]]; then
        mkdir -p "${PROJECT_ROOT_DIR}/build"
        echo "Directory 'build' has been recreated."
    fi
}

echo $(date +"[%Y-%m-%d %H:%M]"): "$0" "$@"
START_TIME=$(date +%s.%N)

PROJECT_BUILD_DIR=$PROJECT_ROOT_DIR/build
LOG_FILE=$PROJECT_BUILD_DIR/build.log
cd "${PROJECT_ROOT_DIR}"

[ ! -d "${PROJECT_ROOT_DIR}/build" ] && mkdir -p ${PROJECT_ROOT_DIR}/build

parse_args "$@" # 解析脚本参数
build_cmake # 执行 CMake 构建

END_TIME=$(date +%s.%N)
EXEC_TIME=$(echo "scale=3; ($END_TIME - $START_TIME) / 1" | bc)
echo -e $(date +"[%Y-%m-%d %H:%M]"): "\033[32m" Build complated in "$EXEC_TIME"s '\033[0m'
