/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef CONSTANT_DEF_H
#define CONSTANT_DEF_H
#include <climits>
#include <cstdint>

namespace scf {
// SN最大长度20，1字节转十六进制2个字符：20*2, +1 结束符
constexpr uint32_t MAX_SERINALNUM_HEX_LEN = 41;
/* 单位: 秒, tls1.3中, 距离上次KU时间1小时，触发key updata */
constexpr uint32_t DEFAULT_KEY_UPDATE_TIME = 3600;
constexpr int MIN_KEY_UPDATE_TIME = 1;        // 1 seconds
constexpr int MAX_KEY_UPDATE_TIME = 31536000; // a year seconds
constexpr uint32_t BUFFER_LEN = 1024;
/* 单位: byte, tls1.3中, 处理数据量超过该值(1GB)，触发key updata */
constexpr uint32_t DEFAULT_KEY_UPDATE_TRAFFIC = (1024 * 1024 * 1024);
constexpr int MIN_KEY_UPDATE_TRAFFIC = 1000; // 1000 bytes
constexpr uint64_t MAX_KEY_UPDATE_TRAFFIC = UINT64_MAX;

constexpr uint32_t ERROR_MSG_SIZE = 64;
constexpr uint32_t MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 * 1024 * 1024: 最大支持文件大小10M
constexpr uint32_t BUF_MAX_LEN = MAX_FILE_SIZE;      // 同最大支持的文件大小

constexpr uint32_t MAX_DATETIME_LEN = 24;
constexpr uint32_t HEX_NUM_BYTES = 2;
constexpr uint32_t CHAR_MASK_LOW_4BITS = 0x0f;
constexpr uint32_t CHAR_MASK_HIGH_4BITS = 0xf0;
constexpr uint32_t SHORT_MASK_LOW_8BITS = 0x00ff;
constexpr uint32_t SHORT_MASK_HIGH_8BITS = 0xff00;
}

#endif // CONSTANT_DEF_H