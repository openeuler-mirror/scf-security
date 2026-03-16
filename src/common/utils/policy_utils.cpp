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

#include <iostream>
#include <map>
#include <mutex>

#include "custom_logger.h"
#include "securec.h"

#include "scf.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "constant_def.h"

namespace scf {
std::mutex g_scfMutex;
bool g_scfInitialized = false;

std::map<int32_t, std::string> errorMap = {
    // 通用错误码
    {SCF_ERRNO_NULL_INPUT, "Null input"},
    {SCF_ERRNO_INVALID_PARAM, "Invalid param"},
    {SCF_ERRNO_MEM_ALLOC, "Memory alloc error"},
    {SCF_ERRNO_MEM_CPY, "Memory copy error"},
    {SCF_ERRNO_NOT_SUPPORT, "Not support"},
    {SCF_ERRNO_INIT_BSM, "Init BSM errorr"},
    {SCF_ERRNO_LARGE_FILE, "Reading large file error"},
    {SCF_ERRNO_SYSTEM_TIME_ERROR, "System time error"},
    {SCF_ERRNO_FILE_PATH_ERROR, "File path error"},
    {SCF_ERRNO_READ_FILE_ERROR, "Read file error"},
    // CAL 模块
    {SCF_ERRNO_INIT_HITLS_BSL, "Init HiTLS bsl error"},
    {SCF_ERRNO_INIT_HITLS_CRYPTO, "Init HiTLS crypto error"},
    {SCF_ERRNO_INIT_HITLS_TLS, "Init HiTLS TLS error"},
    {SCF_ERRNO_NULL_HITLS_CTX, "HiTLS CTX is null"},
    {SCF_ERRNO_NULL_HITLS_CFG, "HiTLS CFG is null"},
    {SCF_ERRNO_SECURE_TRANSPORT, "Secure transport error"},
    {SCF_ERRNO_INIT_OPENSSL, "Init OpenSSL lib error"},
    {SCF_ERRNO_INIT_OPENSSL_ERR, "Load OpenSSL error sting  error"},
    {SCF_ERRNO_INIT_OPENSSL_CRYPTO, "Init OpenSSL crypto error"},
    {SCF_ERRNO_INIT_OPENSSL_ALGO, "Init OpenSSL algo error"},
    {SCF_ERRNO_NULL_CALLBACK, "Callback function is null"},
    {SCF_ERRNO_TLS_ALREADY_INIT, "TLS already initialized"},
    {SCF_ERRNO_INVALID_TLS_TYPE, "Invalid TLS type"},
    {SCF_ERRNO_LOAD_LIB, "Failed to load library"},
    {SCF_ERRNO_UNLOAD_LIB, "Failed to unload library"},
    {SCF_ERRNO_LOAD_SYMBOL, "Failed to load symbol"},
    {SCF_ERRNO_INIT_HITLS_PSE, "Init Hitls pse error"},
    {SCF_ERRNO_INIT_SECUREC, "Init securec error"},
    {SCF_ERRNO_NOT_INIT, "System not initialize"},
    // CONFIG 模块
    {SCF_CFG_ERRNO_PARSE, "CFG parse error"},
    {SCF_CFG_ERRNO_CERT_ARRAY_GET, "CFG cert array get error"},
    {SCF_CFG_ERRNO_CERT_ITEM_GET, "CFG cert item get error"},
    {SCF_CFG_ERRNO_CERT_ADD, "CFG cert add error"},
    {SCF_CFG_ERRNO_PRIVKEY_GET, "CFG private key get error"},
    {SCF_CFG_ERRNO_PRIVKEY_ADD, "CFG private key add error"},
    {SCF_CFG_ERRNO_CIPHER_SUITES_ARRAY_GET, "CFG cipher suites array get error"},
    {SCF_CFG_ERRNO_CIPHER_SUITES_ITEM_GET, "CFG cipher suites item get error"},
    {SCF_CFG_ERRNO_TLS_VERSION_GET, "CFG TLS version get error"},
    {SCF_CFG_ERRNO_TLS_VERSION_SET, "CFG TLS version set error"},
    {SCF_CFG_ERRNO_TLS_FORBID_VERSION_GET, "CFG forbidden TLS version get error"},
    {SCF_CFG_ERRNO_KEY_UPDATE, "CFG key update error"},
    // SSL 实现，对应 ssl 可重新尝试的状态(1 - 256分段)
    {SCF_SSL_ERR_SSL, "SSL error"},
    {SCF_SSL_ERR_WANT_READ, "SSL want read error"},
    {SCF_SSL_ERR_WANT_WRITE, "SSL want write error"},
    {SCF_SSL_ERR_WANT_X509_LOOKUP, "SSL want X509 lookup error"},
    {SCF_SSL_ERR_SYSCALL, "SSL syscall error"},
    {SCF_SSL_ERR_ZERO_RETURN, "SSL zero return error"},
    {SCF_SSL_ERR_WANT_CONNECT, "SSL want connect error"},
    {SCF_SSL_ERR_WANT_ACCEPT, "SSL want accept error"},
    {SCF_SSL_ERR_WANT_ASYNC, "SSL want async error"},
    {SCF_SSL_ERR_WANT_ASYNC_JOB, "SSL want async job error"},
    {SCF_SSL_ERR_WANT_CLIENT_HELLO_CB, "SSL want client hello callback error"},
    {SCF_SSL_ERR_WANT_BACKEP, "SSL want back ep error"},
    // SSL 实现
    {SCF_SSL_ERR_FORMAT_TYPE, "SSL format type error"},
    {SCF_SSL_ERR_STORE_TYPE, "SSL store type error"},
    {SCF_SSL_ERR_PARSE_CERT, "SSL parse certificate error"},
    {SCF_SSL_ERR_ADD_CERT_TO_STORE, "SSL add certificate to store error"},
    {SCF_SSL_ERR_LOAD_KEY, "SSL load key error"},
    {SCF_SSL_ERR_PATH_TOO_LONG, "SSL path too long error"},
    {SCF_SSL_ERR_CHECK_PKEY, "SSL check private key error"},
    {SCF_SSL_ERR_ROLE, "SSL role error"},
    {SCF_SSL_ERR_INIT_TLS13, "SSL initialize TLS 1.3 error"},
    {SCF_SSL_ERR_PSK_CB_HASH, "SSL PSK callback hash error"},
    {SCF_SSL_ERR_GET_VERSION, "SSL get version error"},
    {SCF_SSL_ERR_PSK_MISMATCH, "SSL PSK mismatch"},
    {SCF_SSL_ERR_VERSION, "SSL version error"},
    {SCF_SSL_ERR_POLICY_VERSION, "SSL policy version error"},
    {SCF_SSL_ERR_SET_PASS, "SSL set password error"},
    {SCF_SSL_ERR_PARSE_KEY, "SSL parse key error"},
    {SCF_SSL_ERR_LOAD_CRL, "SSL load CRL error"},
    {SCF_SSL_ERR_SET_ROLE, "SSL set role error"},
    {SCF_SSL_ERR_SESS_SET_CIPHER, "SSL session set cipher error"},
    {SCF_SSL_ERR_SESS_SET_KEY, "SSL session set key error"},
    {SCF_SSL_ERR_SESS_SET_PROTOCOL_VER, "SSL session set protocol version error"},
    {SCF_SSL_ERR_READ, "SSL read error"},
    {SCF_SSL_ERR_WRITE, "SSL write error"},
    {SCF_SSL_ERR_CLOSE, "SSL close error"},
    {SCF_SSL_ERR_SET_CIPHER, "SSL set cipher error"},
    {SCF_SSL_ERR_SET_PROTOCOL_VER, "SSL set protocol version error"},
    {SCF_SSL_ERR_SET_VER_FORBID, "SSL set forbidden version error"},
    {SCF_SSL_ERR_GET_CIPHER, "SSL get cipher error"},
    {SCF_SSL_ERR_ADD_CA_CERT_TO_STORE, "SSL add CA certificate to store error"},
    {SCF_SSL_ERR_ADD_EE_CERT_TO_STORE, "SSL add EE certificate to store error"},
    {SCF_SSL_ERR_ADD_CRL_TO_STORE, "SSL add CRL to store error"},
    {SCF_SSL_ERR_INIT_TLS, "SSL initialize TLS error"},
    {SCF_SSL_ERR_SET_SEC_LEVEL, "SSL set security level error"},
    {SCF_SSL_ERR_SET_SESS_TICKET, "SSL set session ticket error"},
    {SCF_SSL_ERR_SET_SOCKET_FD, "SSL set socket file descriptor error"},
    {SCF_SSL_ERR_SEC_LEVEL_MISMATCH, "SSL security level mismatch error"},
    {SCF_SSL_ERR_GET_CERT_STORE, "SSL get certificate store error"},
    {SCF_SSL_ERR_KEY_UPDATE, "SSL key update error"},
    {SCF_SSL_ERR_IS_INIT_FINISHED, "SSL is initialization finished error"},
    {SCF_SSL_ERR_SET_UPDATE_PARAM, "SSL set update parameter error"},
    {SCF_SSL_ERR_SET_CRL_CHECK_FLAGS, "SSL set CRL check flags error"},
    {SCF_SSL_ERR_LOAD_CA_CERT_CHAIN, "SSL load CA certificate chain error"},
    {SCF_SSL_ERR_ADD_EE_CHAIN_TO_STORE, "SSL add EE chain to store error"},
    {SCF_SSL_ERR_X509_VERIFY_CHAIN, "X509 certificate chain verification error"},
    {SCF_SSL_ERR_SET_EX_DATA, "SSL set extra data error"},
    {SCF_SSL_ERR_SESS_GET_CIPHER, "SSL session get cipher error"},
    {SCF_SSL_ERR_SESS_GET_PROTOCOL_VER, "SSL session get protocol version error"},
};

std::string GetErrorMessageInternal(int32_t errorCode)
{
    static const std::string UNKNOWN_ERROR = "Unknown error code.";
    auto it = errorMap.find(errorCode);
    if (it != errorMap.end()) {
        return it->second;
    } else {
        return UNKNOWN_ERROR;
    }
}

int32_t CheckRole(SCF_ROLE role)
{
    if (role == SCF_ROLE_CLIENT || role == SCF_ROLE_SERVER) {
        return SCF_SUCCESS;
    }
    return SCF_ERRNO_INVALID_PARAM;
}

int32_t CheckVerifyMode(uint32_t verifyMode)
{
    if (verifyMode == SCF_VERIFY_MODE_NONE || verifyMode == SCF_VERIFY_DEFAULT ||
        (verifyMode & SCF_VERIFY_PEER) == SCF_VERIFY_PEER) {
        return SCF_SUCCESS;
    }
    return SCF_ERRNO_INVALID_PARAM;
}

int32_t CheckPolicyMode(SCF_POLICY_MODE policyMode)
{
    if (policyMode == SCF_POLICY_HIGH || policyMode == SCF_POLICY_MIDDLE ||
        policyMode == SCF_POLICY_CUSTOMER) {
        return SCF_SUCCESS;
    }
    return SCF_ERRNO_INVALID_PARAM;
}

int32_t Num2HexStr(const char *num, const uint32_t &numLen, char *hexStr, const uint32_t &hexStrLen)
{
    static const std::string hexTable = "0123456789abcdef";
    char *p = hexStr;

    if (num == nullptr || hexStr == nullptr || hexStrLen == 0) {
        return SCF_ERRNO_INVALID_PARAM;
    }
    // 十六进制数占2个字符，预留结束符空间
    if (numLen == 0 || numLen >= INT32_MAX || numLen * HEX_NUM_BYTES >= hexStrLen) {
        hexStr[0] = '\0';
        return SCF_SUCCESS;
    }
    for (uint32_t i = 0; i < numLen; i++, p += HEX_NUM_BYTES) {
        *p = hexTable[(static_cast<uint8_t>(num[i]) & CHAR_MASK_HIGH_4BITS) >> 4]; // 取 4 bits
        *(p + 1) = hexTable[static_cast<uint8_t>(num[i]) & CHAR_MASK_LOW_4BITS];   // 取 4 bits
    }
    *p = '\0';
    return SCF_SUCCESS;
}

}