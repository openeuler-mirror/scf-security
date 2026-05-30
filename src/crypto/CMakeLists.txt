#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

# 添加 crypto 目录的 include path，使其他模块可以引用 kae_provider_engine.h
target_include_directories(
        scf
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

file(GLOB SRC_CPP *.cpp)

set(SCF_SOURCE_FILES ${SCF_SOURCE_FILES} ${SRC_CPP})

set(SCF_SOURCE_FILES
        ${SCF_SOURCE_FILES}
        PARENT_SCOPE)
