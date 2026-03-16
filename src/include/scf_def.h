/**
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

#ifndef SCF_DEF_H
#define SCF_DEF_H

#include <cstdint>
#include <cstddef>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
namespace scf {
// 宏定义
#define SCF_INIT_FLAG_OPENSSL 1  // 初始化为使用 openssl

#define SCF_CRYPT_MD_UNKNOWN 0
#define SCF_CRYPT_MD_SHA256 10006
#define SCF_CRYPT_MD_SHA384 10007

/**
 * @ingroup  scf
 * @brief    TLS1.2 version. 取值来源于 rfc 5246
 */
#define SCF_SSL_VERSION_TLS12 0x0303u
#define SCF_SSL_VERSION_TLS12_STR "TLSv1.2"

/**
 * @ingroup  scf
 * @brief    TLS 1.3 version. 取值来源于 rfc 8446
 */
#define SCF_SSL_VERSION_TLS13 0x0304u
#define SCF_SSL_VERSION_TLS13_STR "TLSv1.3"

typedef enum {
    /* TLS1.2 cipher suite */
    SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,        // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,        // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,          // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,          // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,    // 取值来源于 rfc 7905
    SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,  // 取值来源于 rfc 7905
    /* TLS1.3 cipher suite. 没有 SCF_SSL_AES_128_CCM_8_SHA256，因为不在公司规范白名单 */
    SCF_SSL_AES_128_GCM_SHA256 = 0x1301,        // 取值来源于 rfc 8446
    SCF_SSL_AES_256_GCM_SHA384 = 0x1302,        // 取值来源于 rfc 8446
    SCF_SSL_CHACHA20_POLY1305_SHA256 = 0x1303,  // 取值来源于 rfc 8446
    SCF_SSL_AES_128_CCM_SHA256 = 0x1304,        // 取值来源于 rfc 8446
} SCF_SSL_CipherSuite;

// 枚举定义
typedef enum SCFRole {
    SCF_ROLE_NONE = 0,    // 未指定
    SCF_ROLE_CLIENT = 1,  // 客户端
    SCF_ROLE_SERVER = 2,  // 服务端
} SCF_ROLE;

typedef enum SCFVerifyMode {
    SCF_VERIFY_MODE_NONE = 0,  // 不校验对端
    SCF_VERIFY_DEFAULT = 1,  // 默认校验方式。使用证书时相当于 VERIFY_PEER 和 VERIFY_FAIL_IF_NO_PEER_CERT 同时生效
    SCF_VERIFY_CUSTOMER = 2,  // 使用用户注册的校验实现，由用户检查。
    SCF_VERIFY_PEER = 4,      // 校验对端
    SCF_VERIFY_FAIL_IF_NO_PEER_CERT = 8,  // 对端无证书则校验失败。应该要和 peer 一起使用
} SCF_VERIFY_MODE;

typedef enum SCFPolicyMode {
    SCF_POLICY_HIGH = 0,    // 高安全，低兼容模式。随安全规范演进。
    SCF_POLICY_MIDDLE = 1,  // 中安全，较高兼容模式。随安全规范演进。
    // CUSTOMER 表示客户化定制。当且仅当业务是出于存量场景兼容性配置，允许业务指定放宽特定校验，自行保证安全性。
    SCF_POLICY_CUSTOMER = 2,
} SCF_POLICY_MODE;

typedef enum SCFStoreType {
    SCF_STORE_FILE_PATH = 0,  // 存储在文件系统上，传入的是文件路径。业务应该传入的是绝对路径
    SCF_STORE_BUFFER,         // 存储在内存中，传入的是文件 buffer
    SCF_STORE_ERROR,          // 不支持的类型
} SCF_STORE_TYPE;

typedef enum SCFStoreFormat {
    SCF_STORE_FORMAT_PEM = 0  // 存储数据是 PEM 格式的
} SCF_STORE_FORMAT;

typedef enum SCFCertType {
    SCF_CERT_TYPE_CA = 0,        // CA 证书
    SCF_CERT_TYPE_EE = 1,        // 设备证书
    SCF_CERT_TYPE_CRL = 2,       // CRL
    SCF_CERT_TYPE_EE_CHAIN = 3,  // 第一本设备证书，最后一本根证书，多本证书构成的证书链
} SCF_CERT_TYPE;

typedef enum LogLevel {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,   // log level debug
    LOG_LEVEL_INFO = 2,    // log level info
    LOG_LEVEL_WARN = 3,    // log level warn
    LOG_LEVEL_ERROR = 4,   // log level error
    LOG_LEVEL_CRITICAL = 5 // log level critical
} LOG_LEVEL;

// 结构体定义
typedef struct SCFFileCtx SCF_FILE_CTX;
typedef struct SCFPolicyCtx SCF_PolicyCtx;  // 安全策略上下文
typedef struct SCFPolicyObj SCF_PolicyObj;  // 安全策略对象实例。Obj 从 Ctx 创建。
typedef void SCF_Session;                     // SCF 会话对象

// 回调函数定义
/**
 * @brief  外部日志函数格式
 */
typedef void (*ExternalLogFunction)(int level, const char *msg);

/**
* @ingroup scf
* @brief  用户校验回调
* @param  storeCtx [IN] 实际是底层 ssl 库的上下文。openssl 是 X509_STORE_CTX 结构，HiTLS 是 SEC_PKI_X509_STORE_CTX_S
结构 # @param  arg [IN] 用户数据
* @return 失败返回错误码，成功返回 SCF_SUCCESS
*/
typedef int32_t (*SCF_AppVerifyFunc)(void *storeCtx, void *arg);

/**
 * @brief  外部解密函数格式
 */
using ExternalDecryptFunction = bool (*)(const uint8_t *content, size_t contentLen, std::vector<std::byte> &plaintext);

/**
 * @ingroup scf
 * @brief  客户端 tls1.3 psk 回调原型
 * @param  obj [IN] 安全策略上下文
 * @param  hashAlgo [IN] tls 算法套的 hash 算法。注意 client hello 时输入的取值会是 0.
 * @param  id [OUT] 客户端给服务端的提示，服务端用于查找使用的 psk。
 * @param  idLen [OUT] id 的长度
 * @param  session [OUT] 创建的会话对象
 * @return 成功返回 SCF_SUCCESS，失败返回错误码
 * @attention 1、客户端在 client hello 阶段，协议栈触发此回调，因为此时还未协商使用哪个算法套，传入的 hashAlgo 会是 0，
 * 因此为 0 是正常情况。
 * 2、配置算法套时，要求配置的算法套的 hash 算法相同。由于 psk
 * 通常仅限于内部通信场景使用，推荐业务固定两端均配置为相同的一 个算法套，保证协商使用的算法是相同的。
 * 3、业务需要设计 id 的内容。例如 id version，psk info 等实现业务的版本对接兼容。
 */
typedef int32_t (*SCF_PskUseSessionCb)(
    SCF_PolicyObj *obj, uint32_t hashAlgo, const uint8_t **id, uint32_t *idLen, SCF_Session **session);

/**
 * @ingroup scf
 * @brief  服务端 tls1.3 psk 回调原型
 * @param  obj [IN] 安全策略上下文
 * @param  identity [IN] 客户端给服务端的提示，服务端用于查找使用的 psk。
 * @param  identityLen [IN] identity 的长度
 * @param  session [OUT] 创建的会话对象
 * @return 成功返回 SCF_SUCCESS，失败返回错误码
 * @attention 1、由于 psk
 * 通常仅限于内部通信场景使用，推荐业务固定两端均配置为相同的一个算法套，保证协商使用的算法是相同的。
 * 服务端涉及和多个客户端对接时，建议对于 hash 算法不同的算法套，业务使用不同的上下文，降低客户端实现难度。
 * 2、业务需要设计 id 的内容。例如 id version，psk info 等实现业务的版本对接兼容。
 */
typedef int32_t (*SCF_PskFindSessionCb)(
    SCF_PolicyObj *obj, const uint8_t *identity, uint32_t identityLen, SCF_Session **session);
}
#ifdef __cplusplus
}
#endif

#endif
