#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#
add_subdirectory(auth)

file(GLOB SRC_CPP *.cpp)

set(SCF_SOURCE_FILES ${SCF_SOURCE_FILES} ${SRC_CPP} )

set(SCF_SOURCE_FILES
        ${SCF_SOURCE_FILES}
        PARENT_SCOPE)
