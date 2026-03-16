/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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

#pragma GCC diagnostic ignored "-Wunused-variable"

#include <sys/types.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

#include <climits>
#include <filesystem>
#include <fstream>

#include "gtest/gtest.h"
#include "custom_logger.h"
#include "securec.h"
#include "test_scf.h"

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"

namespace fs = std::filesystem;
using namespace scf;
namespace test {

#define SCF_PSK_PWD "scf hello"
constexpr static const char *idPskSha256 = "idPskSha256";
constexpr static const char *idPskSha384 = "idPskSha384";
constexpr static const char *pskPlainSha256 = "pskPlainSha256";
constexpr static const char *pskPlainSha384 = "pskPlainSha384";
constexpr int TEST_PSK_ID_MISMATCH = 0;
constexpr int TEST_PSK_ID_PLAIN_SHA256 = 1;
constexpr int TEST_PSK_ID_PLAIN_SHA384 = 2;

static uint16_t g_sslCiphertSuite = 0;
bool StubCheckFilePathAndStat([[maybe_unused]] const std::string &filePath)
{
    return true;
}

bool StubIsAbsolutePath([[maybe_unused]] const std::string &filePath)
{
    return true;
}

int32_t StubSCFSuccess()
{
    return SCF_SUCCESS;
}

bool StubKmcDecryptPassword([[maybe_unused]] const uint8_t *passwd, [[maybe_unused]] size_t passwdLen,
                            std::vector<std::byte> &plaintext)
{
    std::string str = "3Pm4YYRf0QyfSc40";
    size_t len = str.size();
    plaintext.clear();
    plaintext.resize(len);
    for (size_t i = 0; i < len; ++i) {
        plaintext[i] = static_cast<std::byte>(str[i]);
    }
    return true;
}

void ExternalLogFunction(int level, const char *msg)
{
    std::cout << "|level:" << level << " msg:" << msg << '\n';
}

void SCFSmokeTest::SetUp()
{
    SetExternalLogFunction(ExternalLogFunction);
    int32_t ret = SCF_Init(initFlag, const_cast<char *>(libPath.c_str()));
    ASSERT_EQ(ret, SCF_SUCCESS);
    g_sslCiphertSuite = 0;
}

void SCFSmokeTest::TearDown()
{
    if (conn != nullptr) {
        delete conn;
        conn = nullptr;
    }

    SCF_FreePolicyCtx(&m_client);
    SCF_FreePolicyCtx(&m_server);
    SCF_FreePolicyObj(&m_clientObj);
    SCF_FreePolicyObj(&m_serverObj);
    SCF_DeInit();
    g_sslCiphertSuite = 0;
}

void SCFSmokeTest::TestInitServer()
{
    m_server = SCF_CreatePolicyCtx();
    ASSERT_TRUE(m_server != nullptr);
    int32_t ret = SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_SUCCESS);
}

void SCFSmokeTest::TestInitClient()
{
    m_client = SCF_CreatePolicyCtx();
    ASSERT_TRUE(m_client != nullptr);
    int32_t ret = SCF_SetPolicy(m_client, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_SUCCESS);
}

void SCFSmokeTest::TestInitServerObj()
{
    m_serverObj = SCF_CreatePolicyObj(m_server);
    ASSERT_TRUE(m_serverObj != nullptr);
}

void SCFSmokeTest::TestInitClientObj()
{
    m_clientObj = SCF_CreatePolicyObj(m_client);
    ASSERT_TRUE(m_clientObj != nullptr);
}

int64_t SystemMicrosecondsGet()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec;
}

constexpr uint32_t DATA_BUF_LEN = 1024;

int32_t TestSCFRead(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen)
{
    int32_t ret = SCF_ERROR;
    uint32_t retryCnt = 0;
    *readLen = 0;
    // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    while (*readLen == 0 && retryCnt < TEST_READ_RETRY_MAX_CNT) {
        ret = SCF_Read(obj, data, dataLen, readLen);
        if (ret != SCF_SUCCESS) {
            retryCnt++;
            usleep(TEST_USLEEP_TIME);
            continue;
        }
    }
    return ret;
}

void SCFSmokeTest::TestSslReadWrite(uint32_t rwLen)
{
    int32_t ret = SCF_ERROR;
    uint8_t dataSW[DATA_BUF_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // server write
    uint8_t dataSR[DATA_BUF_LEN] = {0};                                                            // server read
    uint32_t dataSLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeSLen = 0;
    uint32_t readSLen = 0;

    uint8_t dataCW[DATA_BUF_LEN] = {
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}; // client write
    uint8_t dataCR[DATA_BUF_LEN] = {0};                                                            // client read
    uint32_t dataCLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeCLen = 0;
    uint32_t readCLen = 0;

    ret = SCF_Write(m_serverObj, dataSW, dataSLen, &writeSLen);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ASSERT_TRUE(writeSLen > 0);
    ret = TestSCFRead(m_clientObj, dataCR, dataCLen, &readCLen);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ASSERT_EQ(writeSLen, readCLen);

    ret = SCF_Write(m_clientObj, dataCW, dataCLen, &writeCLen);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ASSERT_TRUE(writeCLen > 0);
    ret = TestSCFRead(m_serverObj, dataSR, dataSLen, &readSLen);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ASSERT_EQ(writeCLen, readSLen);
}

void SCFSmokeTest::TestSslReadWrite()
{
    TestSslReadWrite(NN_N1024);
}

int32_t TestGetPskAuthType(const uint8_t *identity, uint32_t identityLen)
{
    if (identityLen == strlen(idPskSha256)) {
        if (memcmp(identity, idPskSha256, identityLen) == 0) {
            return TEST_PSK_ID_PLAIN_SHA256;
        }
    }

    if (identityLen == strlen(idPskSha384)) {
        if (memcmp(identity, idPskSha384, identityLen) == 0) {
            return TEST_PSK_ID_PLAIN_SHA384;
        }
    }

    return TEST_PSK_ID_MISMATCH;
}

int32_t TEST_PskUseSessionImplSHA256(
    SCF_PolicyObj *obj, uint32_t hashAlgo, const uint8_t **id, uint32_t *idLen, SCF_Session **session)
{
    int32_t ret = SCF_ERROR;
    if (obj == NULL || id == NULL || idLen == NULL || session == NULL) {
        return SCF_ERRNO_NULL_INPUT;
    }

    uint8_t *psk = nullptr;
    size_t pskLen = 0;

    const void *cipherSuite = nullptr;
    uint8_t tls13Aes128gcmsha256Id[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
    if (hashAlgo == SCF_CRYPT_MD_UNKNOWN) {
        // client hello 时会是 0
        hashAlgo = (g_sslCiphertSuite == SCF_SSL_AES_256_GCM_SHA384) ? SCF_CRYPT_MD_SHA384 : SCF_CRYPT_MD_SHA256;
    }
    switch (hashAlgo) {
        case SCF_CRYPT_MD_SHA256: {
            /* 用户需要自己保证代码里配置的算法套和这里是匹配的。因为仅 hash 算法参数不能区分
             * TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 和 TLS_AES_128_CCM_SHA256 */
            cipherSuite = SCF_CipherFind(obj, tls13Aes128gcmsha256Id);
            *id = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(idPskSha256));
            *idLen = strlen(idPskSha256);
            psk = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(pskPlainSha256));
            pskLen = strlen(pskPlainSha256);
            ret = SCF_SUCCESS;
            break;
        }
        default:
            ret = SCF_SSL_ERR_PSK_CB_HASH;
            break;
    }
    if (ret != SCF_SUCCESS) {
        return ret;
    }

    return TEST_PskCreateSession(psk, pskLen, cipherSuite, session);
}

int32_t TEST_PskFindSessionImplSHA256(
    SCF_PolicyObj *obj, const uint8_t *identity, uint32_t identityLen, SCF_Session **session)
{
    if (obj == NULL || identity == NULL || identityLen == 0 || session == NULL) {
        return SCF_ERRNO_NULL_INPUT;
    }

    int32_t pskAuth = TestGetPskAuthType(identity, identityLen);

    const void *cipherSuite = nullptr;
    uint8_t tls13Aes128gcmsha256Id[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
    uint8_t *psk = nullptr;
    size_t pskLen = 0;
    if (pskAuth == TEST_PSK_ID_PLAIN_SHA256) {
        cipherSuite = SCF_CipherFind(obj, tls13Aes128gcmsha256Id);
        psk = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(pskPlainSha256));
        pskLen = strlen(pskPlainSha256);
    } else {
        return SCF_SSL_ERR_PSK_MISMATCH;
    }

    return TEST_PskCreateSession(psk, pskLen, cipherSuite, session);
}

int32_t TEST_PskFindSessionImpl(
    SCF_PolicyObj *obj, const uint8_t *identity, uint32_t identityLen, SCF_Session **session)
{
    if (obj == nullptr || identity == nullptr || identityLen == 0 || session == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }

    int32_t pskAuth = TestGetPskAuthType(identity, identityLen);

    const void *cipherSuite = nullptr;
    uint8_t *psk = nullptr;
    size_t pskLen = 0;
    if (pskAuth == TEST_PSK_ID_PLAIN_SHA256) {
        uint8_t cipherId[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
        cipherSuite = SCF_CipherFind(obj, cipherId);
        pskLen = strlen(pskPlainSha256);
        memset_s(cipherId, sizeof(cipherId), 0, sizeof(cipherId));
        return TEST_PskCreateSession(reinterpret_cast<const uint8_t *>(pskPlainSha256), pskLen, cipherSuite, session);
    }
    if (pskAuth == TEST_PSK_ID_PLAIN_SHA384) {
        uint8_t cipherId[] = {0x13, 0x02}; // IANA编码 TLS_AES_256_GCM_SHA384
        cipherSuite = SCF_CipherFind(obj, cipherId);
        pskLen = strlen(pskPlainSha384);
        memset_s(cipherId, sizeof(cipherId), 0, sizeof(cipherId));
        return TEST_PskCreateSession(reinterpret_cast<const uint8_t *>(pskPlainSha384), pskLen, cipherSuite, session);
    }
    return SCF_SSL_ERR_PSK_MISMATCH;
}

int32_t TEST_PskUseSessionImpl(
    SCF_PolicyObj *obj, uint32_t hashAlgo, const uint8_t **id, uint32_t *idLen, SCF_Session **session)
{
    int32_t ret = SCF_ERROR;
    if (obj == nullptr || id == nullptr || idLen == nullptr || session == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }

    uint8_t *psk = nullptr;
    size_t pskLen = 0;

    const void *cipherSuite = nullptr;
    if (hashAlgo == SCF_CRYPT_MD_UNKNOWN) {
        // client hello 时会是 0
        hashAlgo = (g_sslCiphertSuite == SCF_SSL_AES_256_GCM_SHA384) ? SCF_CRYPT_MD_SHA384 : SCF_CRYPT_MD_SHA256;
    }
    switch (hashAlgo) {
        case SCF_CRYPT_MD_SHA256: {
            /* 用户需要自己保证代码里配置的算法套和这里是匹配的。因为仅 hash 算法参数不能区分
             * TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 和 TLS_AES_128_CCM_SHA256 */
            uint8_t cipherId[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
            cipherSuite = SCF_CipherFind(obj, cipherId);
            *id = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(idPskSha256));
            *idLen = strlen(idPskSha256);
            pskLen = strlen(pskPlainSha256);
            memset_s(cipherId, sizeof(cipherId), 0, sizeof(cipherId));
            return TEST_PskCreateSession(reinterpret_cast<const uint8_t *>(idPskSha256), pskLen, cipherSuite, session);
        }
        case SCF_CRYPT_MD_SHA384: {
            uint8_t cipherId[] = {0x13, 0x02}; // IANA编码 TLS_AES_256_GCM_SHA384
            cipherSuite = SCF_CipherFind(obj, cipherId);
            *id = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(idPskSha384));
            *idLen = strlen(idPskSha384);
            pskLen = strlen(pskPlainSha384);
            memset_s(cipherId, sizeof(cipherId), 0, sizeof(cipherId));
            return TEST_PskCreateSession(
                reinterpret_cast<const uint8_t *>(pskPlainSha384), pskLen, cipherSuite, session);
        }
        default:
            return SCF_SSL_ERR_PSK_CB_HASH;
    }
}

// 验证SCF_SetPolicy接口入参范围内的值成功
TEST_F(SCFSmokeTest, API_Secure_Communication_Component_14)
{
    SCF_FILE_CTX *tmpPtr = SCF_FileCtxNew();
    ASSERT_TRUE(tmpPtr != nullptr);
    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);

    int32_t ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
    ASSERT_EQ(ret, SCF_SUCCESS);

    SCF_ROLE role = SCF_ROLE_CLIENT;
    uint32_t verifyMode = SCF_VERIFY_PEER;
    SCF_POLICY_MODE policyMode = SCF_POLICY_MIDDLE;
    ret = SCF_GetPolicy(policyctx, &role, &verifyMode, &policyMode);
    SCF_FreePolicyCtx(&policyctx);
    SCF_FileCtxFree(&tmpPtr);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ASSERT_EQ(role, SCF_ROLE_SERVER);
    ASSERT_EQ(verifyMode, SCF_VERIFY_DEFAULT);
    ASSERT_EQ(policyMode, SCF_POLICY_CUSTOMER);
}

// 验证SCF_SetPolicy接口入参范围外的值失败
TEST_F(SCFSmokeTest, API_Secure_Communication_Component_15)
{
    int32_t ret = SCF_SetPolicy(nullptr, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_PolicyCtx *policyctx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyctx != nullptr);
    ret = SCF_SetPolicy(policyctx, SCF_ROLE_NONE, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_ROLE maxRole = (SCF_ROLE)(SCF_ROLE_SERVER + 1);
    ret = SCF_SetPolicy(policyctx, maxRole, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_VERIFY_MODE errMode = (SCF_VERIFY_MODE)(SCF_VERIFY_FAIL_IF_NO_PEER_CERT + 1);
    ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, errMode, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    SCF_POLICY_MODE errPolicyMode = SCF_POLICY_MIDDLE;
    ret = SCF_SetPolicy(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, errPolicyMode);
    SCF_FreePolicyCtx(&policyctx);
    ASSERT_EQ(ret, SCF_SUCCESS);
}

// 验证SCF_SetPskFindSessionCallback接口入参范围内的值成功
TEST_F(SCFSmokeTest, API_Secure_Communication_Component_42)
{
    int32_t ret;
    // 服务端配置安全策略
    SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyCtx != nullptr);
    ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_SUCCESS);
    ret = SCF_SetPskFindSessionCallback(policyCtx, nullptr);
    ASSERT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyCtx(&policyCtx);
}

// 验证SCF_SetPskFindSessionCallback接口入参范围外的值失败
TEST_F(SCFSmokeTest, API_Secure_Communication_Component_43)
{
    int32_t ret;
    // 服务端配置安全策略
    SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyCtx != nullptr);
    ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_SUCCESS);
    // 设置ctx为空
    ret = SCF_SetPskFindSessionCallback(nullptr, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreePolicyCtx(&policyCtx);
}

// 验证SCF_SetPskUseSessionCallback接口入参范围内的值成功
TEST_F(SCFSmokeTest, API_Secure_Communication_Component_46)
{
    int32_t ret;
    // 服务端配置安全策略
    SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyCtx != nullptr);
    ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_SUCCESS);
    // 2、设置psk
    ret = SCF_SetPskUseSessionCallback(policyCtx, nullptr);
    ASSERT_EQ(ret, SCF_SUCCESS);
    SCF_FreePolicyCtx(&policyCtx);
}

// 验证SCF_SetPskUseSessionCallback接口入参范围内的值失败
TEST_F(SCFSmokeTest, API_Secure_Communication_Component_47)
{
    int32_t ret;
    // 服务端配置安全策略
    SCF_PolicyCtx *policyCtx = SCF_CreatePolicyCtx();
    ASSERT_TRUE(policyCtx != nullptr);
    ret = SCF_SetPolicy(policyCtx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_SUCCESS);
    // 设置ctx为空
    ret = SCF_SetPskUseSessionCallback(nullptr, nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreePolicyCtx(&policyCtx);
}
} // namespace test
