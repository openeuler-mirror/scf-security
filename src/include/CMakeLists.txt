#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#
install(
        FILES ${CMAKE_CURRENT_LIST_DIR}/scf.h
        ${CMAKE_CURRENT_LIST_DIR}/scf_def.h
        ${CMAKE_CURRENT_LIST_DIR}/scf_errno.h
        ${CMAKE_CURRENT_LIST_DIR}/scf_ssl.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        PERMISSIONS  OWNER_READ )
