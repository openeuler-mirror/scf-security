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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wcast-qual"

#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "gtest/gtest.h"
#include "secodefuzz/secodeFuzz.h"
#include "securec.h"
#include "test_tcp_client.h"
#include "test_tcp_common.h"
#include "test_tcp_server.h"

#include "custom_logger.h"
#include "scf.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "scf_ssl.h"

using namespace scf;
namespace scfFuzz {

const uint32_t ARG_MAX_LEN = 160;
const uint32_t ARG_MAX_NUM = 100;
char g_corpusPath[256];    // seed file path
char g_reportPath[512];    // running duration report
char g_reproducePath[256]; // path of the crash sample file
long g_count = 30000000;         // number of running times
long g_time = 3600 * 3;    // running duration
long g_isReproduce = 0;    // reproduction flag
long g_seed = 0;

class TestSCFPolicy : public testing ::Test {};

void ExternalLogFunction(int level, const char *msg)
{
    std::cout << "|Test log print|level:" << level << " msg:" << msg << std::endl;
}

TEST_F(TestSCFPolicy, SCFInit)
{
    printf("------TestInit start------\n");
    DT_Set_Report_Path("./");
    DT_Set_Running_Time_Second(g_time);

    void *settings = nullptr;
    int role;
    int verifyMode;
    int policyMode;
    int64_t count = 0;
    char certTimeBuffer[20] = {0};
    uint32_t length = 20;
    uint16_t cipherSuies = 1;
    uint8_t pwdBuf = 1;
    DT_Enable_Support_Loop(1);
    DT_Enable_Leak_Check(0, 0);
    DT_FUZZ_START(g_seed, g_count, "SCFInit", g_isReproduce)
    {
        uint64_t flag = *(s32 *)DT_SetGetNumberRange(&g_Element[0], 0, 0, 10);
        int32_t ret = SCF_Init(flag, nullptr);
        ret = SCF_Init(flag, settings);
        GetErrorMessage(ret);
        auto *m_client = SCF_CreatePolicyCtx();

        role = *(s32 *)DT_SetGetNumberRange(&g_Element[1], 0, 0, 3);        // 1 3 enum fuzz test value
        verifyMode = *(s32 *)DT_SetGetNumberRange(&g_Element[2], 0, 0, 16); // 2 16 enum fuzz test value
        policyMode = *(s32 *)DT_SetGetNumberRange(&g_Element[3], 0, 0, 3);  // 3 3 enum fuzz test value
        SCF_SetPolicy(nullptr, SCFRole(role), SCF_VERIFY_MODE(verifyMode), SCF_POLICY_MODE(policyMode));
        SCF_SetPolicy(m_client, SCFRole(role), SCF_VERIFY_MODE(verifyMode), SCF_POLICY_MODE(policyMode));
        auto *fileCtx = SCF_FileCtxNew();
        SCF_FileCtxSetBuf(nullptr, SCF_STORE_FILE_PATH, nullptr, 0, SCF_STORE_FORMAT_PEM);
        SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, &pwdBuf, 0, SCF_STORE_FORMAT_PEM);
        SCF_FileCtxSetPwd(fileCtx, &pwdBuf, 1, "", "");
        SCF_FileCtxSetPwd(fileCtx, nullptr, 1, "", "");
        SCF_FileCtxSetPwd(nullptr, nullptr, 0, "", "");
        SCF_AddCert(m_client, nullptr, SCF_CERT_TYPE_CA);

        SCF_CreatePolicyObj(nullptr);
        auto *m_clientObj = SCF_CreatePolicyObj(m_client);

        SCFRole getRole = SCF_ROLE_NONE;
        uint32_t getVerifyMode = SCF_VERIFY_DEFAULT;
        SCF_POLICY_MODE getPolicyMode = SCF_POLICY_MIDDLE;
        SCF_GetPolicy(m_client, &getRole, &getVerifyMode, &getPolicyMode);
        SetExternalLogFunction(nullptr);
        SetExternalLogFunction(ExternalLogFunction);

        SCF_GetCurrentCert(nullptr);
        SCF_GetPeerCert(nullptr);
        SCF_GetCertStartTime(nullptr, certTimeBuffer, length);
        SCF_GetCertEndTime(nullptr, certTimeBuffer, length);
        SCF_SetCipherSuites(m_client, nullptr, 0);
        SCF_SetCipherSuites(m_client, &cipherSuies, 0);
        SCF_SetProtocolVersion(nullptr, 0, 0, nullptr, 0);
        SCF_CheckPrivateKey(nullptr);
        SCF_SetPskFindSessionCallback(nullptr, SCF_PskFindSessionCb(nullptr));
        SCF_SetPskFindSessionCallback(m_client, SCF_PskFindSessionCb(nullptr));
        SCF_SetPskUseSessionCallback(nullptr, SCF_PskUseSessionCb(nullptr));
        SCF_SetPskUseSessionCallback(m_client, SCF_PskUseSessionCb(nullptr));

        SCF_GetProtocolVersion(nullptr);
        SCF_GetCipherSuites(m_client, nullptr, 0, 0);
        SCF_GetCertVersion(nullptr);
        SCF_GetCertStartTime(nullptr, certTimeBuffer, length);
        SCF_GetCertEndTime(nullptr, certTimeBuffer, length);
        SCF_GetCertSerialNumber(nullptr, &length);

        SCF_SetKey(m_client, nullptr);

        SCF_FreePolicyCtx(m_client);
        SCF_FreePolicyObj(m_clientObj);
        SCF_FileCtxFree(fileCtx);
        SCF_FreePolicyObj(nullptr);
        SCF_FreePolicyCtx(nullptr);
        SCF_FreeCert(nullptr);
        SCF_Read(nullptr, nullptr, 0, nullptr);
        SCF_Write(nullptr, nullptr, 0, nullptr);
        SCF_ObjKeyUpdate(nullptr);

        SCF_DeInit();

        SCF_GetCurrentCert(nullptr);
        SCF_GetPeerCert(nullptr);
        SCF_GetCertStartTime(nullptr, certTimeBuffer, length);
        SCF_GetCertEndTime(nullptr, certTimeBuffer, length);
        SCF_SetCipherSuites(m_client, nullptr, 0);
        SCF_SetCipherSuites(m_client, &cipherSuies, 0);
        SCF_SetProtocolVersion(nullptr, 0, 0, nullptr, 0);
        SCF_CheckPrivateKey(nullptr);
        SCF_SetPskFindSessionCallback(nullptr, SCF_PskFindSessionCb(nullptr));
        SCF_SetPskFindSessionCallback(m_client, SCF_PskFindSessionCb(nullptr));
        SCF_SetPskUseSessionCallback(nullptr, SCF_PskUseSessionCb(nullptr));
        SCF_SetPskUseSessionCallback(m_client, SCF_PskUseSessionCb(nullptr));
        SCF_SetConfigFile(nullptr, nullptr);
        SCF_Read(nullptr, nullptr, 0, nullptr);
        SCF_Write(nullptr, nullptr, 0, nullptr);
        SCF_SetUserData(nullptr, nullptr);
        SCF_GetUserData(nullptr);
        SCF_ObjKeyUpdate(nullptr);
        count++;
        CCSEC_LOG_INFO("count " << count);
    }
    DT_FUZZ_END()
    printf("------TestInit end------\n");
}

static uint16_t g_sslCiphertSuite = 0;
uint16_t *g_mCipherSuites = nullptr;
size_t g_mCipherSuitesLen = 0;
uint32_t g_mRwLen = 2048; // 传输的数据大小
SCF_PolicyCtx *m_client = nullptr;
SCF_PolicyObj *m_clientObj = nullptr;
SCF_PolicyCtx *m_server = nullptr;
SCF_PolicyObj *m_serverObj = nullptr;
test::fw::TestTcpConnection *m_client_conn = nullptr;
test::fw::TestTcpConnection *m_server_conn = nullptr;
constexpr uint32_t DATA_BUF_LEN = 4096;

constexpr int TEST_PSK_ID_MISMATCH = 0;
constexpr int TEST_PSK_ID_PLAIN_SHA256 = 1;
constexpr int TEST_PSK_ID_PLAIN_SHA384 = 2;

uint32_t *g_mForbidenbersion = nullptr;
size_t g_mForbidenbersionLen = 0;

constexpr static const char *ID_PSK_SHA256 = "ID_PSK_SHA256";
constexpr static const char *ID_PSK_SHA384 = "ID_PSK_SHA384";
constexpr static const char *PSK_PLAIN_SHA256 = "PSK_PLAIN_SHA256";
constexpr static const char *PSK_PLAIN_SHA384 = "PSK_PLAIN_SHA384";

int32_t SCFRead(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen)
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

void TESTSslReadWrite(uint32_t rwLen)
{
    int32_t ret = SCF_ERROR;
    uint8_t dataSW[DATA_BUF_LEN] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}; // server write
    uint8_t dataSR[DATA_BUF_LEN] = {0};                                                            // server read
    uint32_t dataSLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeSLen = 0;
    uint32_t readSLen = 0;
    static int cnt = 0;
    cnt++;

    uint8_t dataCW[DATA_BUF_LEN] = {
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}; // client write
    uint8_t dataCR[DATA_BUF_LEN] = {0};                                                            // client read
    uint32_t dataCLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeCLen = 0;
    uint32_t readCLen = 0;

    ret = SCF_Write(m_serverObj, dataSW, dataSLen, &writeSLen);
    if (ret != SCF_SUCCESS || writeSLen <= 0) {
        std::cout << "SCF_Write error" << ret << ". ret msg: " << GetErrorMessage(ret) << std::endl;
    }
    std::cout << "length " << writeSLen << std::endl;

    ret = SCFRead(m_clientObj, dataCR, dataCLen, &readCLen);
    if (ret != SCF_SUCCESS || rwLen != readCLen) {
        std::cout << "SCFRead error" << ret << ". ret msg: " << GetErrorMessage(ret) << std::endl;
    }
    std::cout << "length =========" << readCLen << std::endl;

    ret = SCF_Write(m_clientObj, dataCW, dataCLen, &writeCLen);
    if (ret != SCF_SUCCESS || writeCLen <= 0) {
        std::cout << "SCF_Write error" << ret << ". ret msg: " << GetErrorMessage(ret) << std::endl;
    }

    ret = SCFRead(m_serverObj, dataSR, dataSLen, &readSLen);
    if (ret != SCF_SUCCESS || rwLen != readSLen) {
        std::cout << "SCFRead error" << ret << ". ret msg: " << GetErrorMessage(ret) << std::endl;
    }
}

// 参考 openssl 的 create_bare_ssl_connection
int CreateServerBareSslConnection(SCF_PolicyObj *serverssl, int want)
{
    int rets = -1;
    int err = 0;
    int abortctr = 0;
    int servererr = 0;

    do {
        err = SCF_SSL_ERR_WANT_WRITE;
        while (!servererr && rets != SCF_SUCCESS && err == SCF_SSL_ERR_WANT_WRITE) {
            rets = SCF_Accept(serverssl);
            std::cout << "SCF_Accept rets:" << rets;
            err = rets;
            if (abortctr % TEST_REPEAT_LOG_TIME == 0) {
                printf("SSL_accept %d\n", rets);
            }
        }

        if (!servererr && rets != SCF_SUCCESS && err != SCF_SSL_ERR_WANT_READ) {
            printf("SSL_accept() failed %d, %d\n", rets, err);
            if (want != SCF_ERROR) {
                // 不符合预期
                printf("SSL server not expect\n");
            }
            servererr = 1; // 实际异常
        }
        if (want != SCF_SUCCESS && err == want) {
            // 符合预期的异常
            printf("want != SCF_SUCCESS && err == want\n");
            return 0;
        }
        if (servererr) {
            // 不符合预期的异常
            printf("servererr\n");
            return 0;
        }
        if (++abortctr == TEST_MAXLOOPS) {
            printf("No progress made\n");
            return 0;
        }
        usleep(TEST_USLEEP_TIME); // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    } while (rets != SCF_SUCCESS);

    return 1;
}

int32_t TEST_SitGetPskAuthType(const uint8_t *identity, uint32_t identityLen)
{
    if (identityLen == strlen(ID_PSK_SHA256)) {
        if (memcmp(identity, ID_PSK_SHA256, identityLen) == 0) {
            return TEST_PSK_ID_PLAIN_SHA256;
        }
    }

    if (identityLen == strlen(ID_PSK_SHA384)) {
        if (memcmp(identity, ID_PSK_SHA384, identityLen) == 0) {
            return TEST_PSK_ID_PLAIN_SHA384;
        }
    }
    return TEST_PSK_ID_MISMATCH;
}

int32_t TEST_PskCreateSession(uint8_t *psk, size_t pskLen, const void *cipherSuite, SCF_Session **session)
{
    SCF_Session *sess = SCF_SessionNew();
    if (sess == NULL) {
        return SCF_ERRNO_MEM_ALLOC;
    }

    // 业务应该需要加密存储 psk，使用时临时解密为明文使用，使用后清理敏感数据
    int32_t ret = SCF_SessionSetMasterKey(sess, psk, pskLen);
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(sess);
        return ret;
    }

    ret = SCF_SessionSetCipher(sess, cipherSuite, 2); // 当前rfc规定为2
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(sess);
        return ret;
    }
    // 参考 openssl 自身实现，建议写死。业务上会知道配置使用的 psk 是 1.3 还是 1.2 的。不同版本配置的回调也是不同的。
    ret = SCF_SessionSetProtocolVersion(sess, SCF_SSL_VERSION_TLS13_STR);
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(sess);
        return ret;
    }
    *session = sess;
    return ret;
}

int32_t TEST_SitPskFindSessionImpl(
    SCF_PolicyObj *obj, const uint8_t *identity, uint32_t identityLen, SCF_Session **session)
{
    if (obj == NULL || identity == NULL || identityLen == 0 || session == NULL) {
        return SCF_ERRNO_NULL_INPUT;
    }

    int32_t pskAuth = TEST_SitGetPskAuthType(identity, identityLen);

    const void *cipherSuite = nullptr;
    uint8_t tls13Aes128gcmsha256Id[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
    uint8_t tls13Aes256gcmsha384Id[] = {0x13, 0x02}; // IANA编码 TLS_AES_256_GCM_SHA384
    uint8_t *psk = nullptr;
    size_t pskLen = 0;
    if (pskAuth == TEST_PSK_ID_PLAIN_SHA256) {
        cipherSuite = SCF_CipherFind(obj, tls13Aes128gcmsha256Id);
        psk = (uint8_t *)PSK_PLAIN_SHA256;
        pskLen = strlen(PSK_PLAIN_SHA256);
    } else if (pskAuth == TEST_PSK_ID_PLAIN_SHA384) {
        cipherSuite = SCF_CipherFind(obj, tls13Aes256gcmsha384Id);
        psk = (uint8_t *)PSK_PLAIN_SHA384;
        pskLen = strlen(PSK_PLAIN_SHA384);
    } else {
        return SCF_SSL_ERR_PSK_MISMATCH;
    }
    CCSEC_LOG_INFO("TEST_SitPskFindSessionImpl done");
    return TEST_PskCreateSession(psk, pskLen, cipherSuite, session);
}

int32_t TEST_SitPskUseSessionImpl(
    SCF_PolicyObj *obj, uint32_t hashAlgo, const uint8_t **id, uint32_t *idLen, SCF_Session **session)
{
    int32_t ret = SCF_ERROR;
    if (obj == NULL || id == NULL || idLen == NULL || session == NULL) {
        return SCF_ERRNO_NULL_INPUT;
    }
    uint8_t *psk = nullptr;
    size_t pskLen = 0;
    const void *cipherSuite = nullptr;
    uint8_t tls13Aes128gcmsha256Id[] = {0x13, 0x01}; // 0x13, 0x01 IANA编码 TLS_AES_128_GCM_SHA256
    uint8_t tls13Aes256gcmsha384Id[] = {0x13, 0x02}; // 0x13, 0x02 IANA编码 TLS_AES_256_GCM_SHA384
    if (hashAlgo == SCF_CRYPT_MD_UNKNOWN) {
        // client hello 时会是 0
        hashAlgo = (g_sslCiphertSuite == SCF_SSL_AES_256_GCM_SHA384) ? SCF_CRYPT_MD_SHA384 : SCF_CRYPT_MD_SHA256;
    }
    switch (hashAlgo) {
        case SCF_CRYPT_MD_SHA256: {
            /* 用户需要自己保证代码里配置的算法套和这里是匹配的。因为仅 hash 算法参数不能区分
             * TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 和 TLS_AES_128_CCM_SHA256 */
            cipherSuite = SCF_CipherFind(obj, tls13Aes128gcmsha256Id);
            *id = (const uint8_t *)ID_PSK_SHA256;
            *idLen = strlen(ID_PSK_SHA256);
            psk = (uint8_t *)PSK_PLAIN_SHA256;
            pskLen = strlen(PSK_PLAIN_SHA256);
            ret = SCF_SUCCESS;
            break;
        }
        case SCF_CRYPT_MD_SHA384: {
            cipherSuite = SCF_CipherFind(obj, tls13Aes256gcmsha384Id);
            *id = (const uint8_t *)ID_PSK_SHA384;
            *idLen = strlen(ID_PSK_SHA384);
            psk = (uint8_t *)PSK_PLAIN_SHA384;
            pskLen = strlen(PSK_PLAIN_SHA384);
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
    CCSEC_LOG_INFO("TEST_SitPskFindSessionImpl done");
    return TEST_PskCreateSession(psk, pskLen, cipherSuite, session);
}

void ClientSslReadWrite(uint32_t rwLen)
{
    static int cnt = 0;
    cnt++;
    int32_t ret = SCF_ERROR;

    uint8_t dataCW[DATA_BUF_LEN] = {
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}; // client write
    uint8_t dataCR[DATA_BUF_LEN] = {0};                                                            // client read
    uint32_t dataCLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeCLen = 0;
    uint32_t readCLen = 0;

    ret = SCFRead(m_clientObj, dataCR, dataCLen, &readCLen);
    if (ret != SCF_SUCCESS || rwLen != readCLen) {
        std::cout << "SCFRead error" << ret << ". ret msg: " << GetErrorMessage(ret) << std::endl;
    }
    std::cout << "length =========" << readCLen << std::endl;

    ret = SCF_Write(m_clientObj, dataCW, dataCLen, &writeCLen);
    if (ret != SCF_SUCCESS || writeCLen <= 0) {
        std::cout << "SCF_Write error" << ret << ". ret msg: " << GetErrorMessage(ret) << std::endl;
    }
}

int CreateClientBareSslConnection(SCF_PolicyObj *clientssl, int want)
{
    int retc = -1;
    int err = 0;
    int abortctr = 0;
    int servererr = 0;
    int clienterr = 0;

    do {
        err = SCF_SSL_ERR_WANT_WRITE;
        // 1. 客户端没有异常；2.建链还没成功；3.建筑状态还是 WANT_WRITE
        while (!clienterr && retc != SCF_SUCCESS && err == SCF_SSL_ERR_WANT_WRITE) {
            retc = SCF_Connect(clientssl);
            std::cout << "SCF_Connect rets:" << retc;
            err = retc;
            if (abortctr % TEST_REPEAT_LOG_TIME == 0) {
                printf("SSL_connect %d\n", retc);
            }
        }

        // 判断是实际异常，还是建链等待状态
        if (!clienterr && retc != SCF_SUCCESS && err != SCF_SSL_ERR_WANT_READ) {
            printf("SSL_connect() failed %d, %d\n", retc, err);
            if (want != SCF_ERROR) {
                // 不符合预期
                printf("SSL client not expect\n");
            }
            clienterr = 1; // 实际异常
        }
        if (want != SCF_SUCCESS && err == want) {
            // 符合预期的异常
            printf("want != SCF_SUCCESS && err == want\n");
            return 0;
        }
        if (clienterr) {
            // 不符合预期的异常
            printf("clienterr\n");
            return 0;
        }
        if (++abortctr == TEST_MAXLOOPS) {
            printf("No progress made\n");
            return 0;
        }
        usleep(TEST_USLEEP_TIME); // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    } while (retc != SCF_SUCCESS);
    return 1;
}

// 参考 openssl 的 create_bare_ssl_connection
int Test_CreateBareSslConnection(SCF_PolicyObj *serverssl, SCF_PolicyObj *clientssl, int want)
{
    int retc = -1;
    int rets = -1;
    int err = 0;
    int abortctr = 0;
    int clienterr = 0;
    int servererr = 0;

    do {
        err = SCF_SSL_ERR_WANT_WRITE;
        // 1. 客户端没有异常；2.建链还没成功；3.建筑状态还是 WANT_WRITE
        while (!clienterr && retc != SCF_SUCCESS && err == SCF_SSL_ERR_WANT_WRITE) {
            retc = SCF_Connect(clientssl);
            err = retc;
            if (abortctr % TEST_REPEAT_LOG_TIME == 0) {
                printf("SSL_connect %d\n", retc);
            }
        }

        // 判断是实际异常，还是建链等待状态
        if (!clienterr && retc != SCF_SUCCESS && err != SCF_SSL_ERR_WANT_READ) {
            printf("SSL_connect() failed %d, %d\n", retc, err);
            if (want != SCF_ERROR) {
                // 不符合预期
                printf("SSL client not expect\n");
            }
            clienterr = 1; // 实际异常
        }

        err = SCF_SSL_ERR_WANT_WRITE;
        while (!servererr && rets != SCF_SUCCESS && err == SCF_SSL_ERR_WANT_WRITE) {
            rets = SCF_Accept(serverssl);
            err = rets;
            if (abortctr % TEST_REPEAT_LOG_TIME == 0) {
                printf("SSL_accept %d\n", rets);
            }
        }

        if (!servererr && rets != SCF_SUCCESS && err != SCF_SSL_ERR_WANT_READ) {
            printf("SSL_accept() failed %d, %d\n", rets, err);
            if (want != SCF_ERROR) {
                // 不符合预期
                printf("SSL server not expect\n");
            }
            servererr = 1; // 实际异常
        }
        if (want != SCF_SUCCESS && err == want) {
            // 符合预期的异常
            printf("want != SCF_SUCCESS && err == want\n");
            return 0;
        }
        if (clienterr && servererr) {
            // 不符合预期的异常
            printf("clienterr && servererr\n");
            return 0;
        }
        if (++abortctr == TEST_MAXLOOPS) {
            printf("No progress made\n");
            return 0;
        }
        usleep(TEST_USLEEP_TIME); // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    } while (retc != SCF_SUCCESS || rets != SCF_SUCCESS);
    printf("return xTTTT \n");
    return 1;
}

TEST_F(TestSCFPolicy, SCFPSKConn)
{
    printf("------TestConn PSK start------\n");
    DT_Set_Report_Path("./");
    DT_Set_Running_Time_Second(g_time);

    void *settings = nullptr;
    g_sslCiphertSuite = SCF_SSL_AES_256_GCM_SHA384;
    uint16_t cipherSuites[] = {
        SCF_SSL_AES_256_GCM_SHA384,
    };
    g_mCipherSuites = cipherSuites;
    g_mCipherSuitesLen = sizeof(cipherSuites) / sizeof(uint16_t);
    g_mRwLen = 1024; // 1024 ssl read write length
    uint32_t forbidensut[] = {0x0303u};
    g_mForbidenbersion = forbidensut;
    g_mForbidenbersionLen = sizeof(forbidensut) / sizeof(uint32_t);
    int64_t count = 0;
    DT_Enable_Support_Loop(1);
    DT_Enable_Leak_Check(0, 0);
    DT_FUZZ_START(g_seed, g_count, "SCFConn", g_isReproduce)
    {
        // init client obj
        SCF_Init(SCF_INIT_FLAG_HITLS, nullptr);
        m_client = SCF_CreatePolicyCtx();
        SCF_SetPolicy(m_client, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        SCF_SetKeyAutoUpdateParam(m_client, true, 1, 1000); // 1 1000 test fuzz value
        SCF_SetCipherSuites(m_client, g_mCipherSuites, g_mCipherSuitesLen);
        SCF_SetProtocolVersion(
            m_client, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, forbidensut, g_mForbidenbersionLen);
        SCF_SetPskUseSessionCallback(m_client, TEST_SitPskUseSessionImpl);
        m_clientObj = SCF_CreatePolicyObj(m_client);

        // init server obj
        m_server = SCF_CreatePolicyCtx();
        SCF_SetPolicy(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
        SCF_SetCipherSuites(m_server, g_mCipherSuites, g_mCipherSuitesLen);
        SCF_SetProtocolVersion(m_server, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, g_mForbidenbersion, 0);
        SCF_SetPskFindSessionCallback(m_server, TEST_SitPskFindSessionImpl);
        m_serverObj = SCF_CreatePolicyObj(m_server);

        // init server tcp conn
        test::fw::TestTcpServer testServer(BASE_IP, 9447); // 9447 服务段IP
        testServer.Start();

        // init client tcp conn
        test::fw::TestTcpClient testClient(BASE_IP, 9447); // 9447 客户端ip
        testClient.Connect(BASE_IP, 9447, m_client_conn);  // 9447 服务端ip

        SCF_SetFd(m_serverObj, testServer.GetAcceptFd());
        SCF_SetFd(m_clientObj, m_client_conn->GetFd());

        Test_CreateBareSslConnection(m_serverObj, m_clientObj, SCF_SUCCESS);
        TESTSslReadWrite(g_mRwLen);
        SCF_Close(m_clientObj);
        SCF_CheckPrivateKey(m_client);

        auto session = SCF_SessionNew();
        SCF_SessionFree(session);
        CCSEC_LOG_INFO("ServerSslReadWrite");
        SCF_Close(m_clientObj);
        SCF_FreePolicyCtx(m_client);
        SCF_FreePolicyObj(m_clientObj);
        SCF_FreePolicyCtx(m_server);
        SCF_FreePolicyObj(m_serverObj);
        count++;
        CCSEC_LOG_INFO("count " << count);
        delete m_client_conn;
        m_client_conn = nullptr;
    }
    DT_FUZZ_END()
    printf("------TestConn PSK end------\n");
}

TEST_F(TestSCFPolicy, SCFCertConn)
{
    printf("------TestConn Cert start------\n");
    DT_Set_Report_Path("./");
    DT_Set_Running_Time_Second(g_time);

    void *settings = nullptr;
    g_sslCiphertSuite = SCF_SSL_AES_256_GCM_SHA384;
    uint16_t cipherSuites[] = {
        SCF_SSL_AES_256_GCM_SHA384,
    };
    g_mCipherSuites = cipherSuites;
    g_mCipherSuitesLen = sizeof(cipherSuites) / sizeof(uint16_t);
    g_mRwLen = 1024; // 1024 ssl read write length
    uint32_t forbidensut[] = {0x0303u};
    g_mForbidenbersion = forbidensut;
    g_mForbidenbersionLen = sizeof(forbidensut) / sizeof(uint32_t);
    char certTimeBuffer[20] = {0};
    int length = 20;
    uint16_t data[20] = {0};
    uint32_t dataLen = 20;
    uint32_t cipherSuitesSize;
    uint64_t lastKeyUpdateTime = 100;
    uint32_t timeInterval = 100;
    uint64_t remainTraffic = 100;
    uint16_t userData = 9999;
    uint32_t certSerialNumber = 1;
    int64_t count = 0;
    DT_Enable_Support_Loop(1);
    DT_Enable_Leak_Check(0, 0);
    DT_FUZZ_START(g_seed, g_count, "SCFConn", g_isReproduce)
    {
        // init client obj
        SCF_Init(SCF_INIT_FLAG_HITLS, nullptr);
        m_client = SCF_CreatePolicyCtx();
        SCF_SetPolicy(
            m_client, SCF_ROLE_CLIENT, SCF_VERIFY_PEER | SCF_VERIFY_FAIL_IF_NO_PEER_CERT, SCF_POLICY_MIDDLE);
        SCF_SetKeyAutoUpdateParam(m_client, true, 1, 1000); // 1 1000 fuzz test value
        SCF_SetConfigFile(m_client, "/mylocal/code/xx/SCF/test/scfdemo/client.json");
        m_clientObj = SCF_CreatePolicyObj(m_client);

        // init server obj
        m_server = SCF_CreatePolicyCtx();
        SCF_SetPolicy(
            m_server, SCF_ROLE_SERVER, SCF_VERIFY_PEER | SCF_VERIFY_FAIL_IF_NO_PEER_CERT, SCF_POLICY_MIDDLE);
        SCF_SetConfigFile(m_server, "/mylocal/code/xx/SCF/test/scfdemo/server.json");
        m_serverObj = SCF_CreatePolicyObj(m_server);

        // init server tcp conn
        test::fw::TestTcpServer testServer(BASE_IP, 9446); // 9446 服务段IP
        testServer.Start();

        // init client tcp conn
        test::fw::TestTcpClient testClient(BASE_IP, 9446); // 9446 客户端ip
        testClient.Connect(BASE_IP, 9446, m_client_conn);  // 9446 服务端ip

        SCF_SetFd(m_serverObj, testServer.GetAcceptFd());
        SCF_SetFd(m_clientObj, m_client_conn->GetFd());

        Test_CreateBareSslConnection(m_serverObj, m_clientObj, SCF_SUCCESS);
        SCF_CheckPrivateKey(m_client);

        TESTSslReadWrite(g_mRwLen);
        CCSEC_LOG_INFO("ServerSslReadWrite");

        auto certCtx = SCF_GetCurrentCert(m_clientObj);
        if (certCtx == nullptr) {
            std::cout << "cert is null ptr " << std::endl;
        }
        SCF_SetAppVerifyCallback(m_client, SCF_AppVerifyFunc(certCtx), nullptr);
        SCF_GetProtocolVersion(m_clientObj);
        SCF_GetCertStartTime(certCtx, certTimeBuffer, length);
        CCSEC_LOG_INFO("GetCertStartTims :" << certTimeBuffer);
        SCF_GetCertEndTime(certCtx, certTimeBuffer, length);
        CCSEC_LOG_INFO("SCF_GetCertEndTime :" << certTimeBuffer);
        SCF_GetCertVersion(certCtx);
        SCF_GetCipherSuites(m_client, data, dataLen, &cipherSuitesSize);
        CCSEC_LOG_INFO("getCipherSuites data: " << data);
        SCF_ObjKeyUpdate(m_clientObj);
        SCF_GetKeyUpdateInfo(m_clientObj, &lastKeyUpdateTime, &timeInterval, &remainTraffic);
        CCSEC_LOG_INFO("GetKeyUpdateInfo: " << "lastKeyUpdateTime " << lastKeyUpdateTime << " timeInterval "
                                            << timeInterval << " remainTraffic " << remainTraffic);
        certCtx = SCF_GetPeerCert(m_clientObj);
        SCF_GetCertSerialNumber(certCtx, &certSerialNumber);
        CCSEC_LOG_INFO("GetCertSerialNumber: " << certSerialNumber);

        SCF_SetUserData(m_clientObj, &userData);
        auto getUserData = SCF_GetUserData(m_clientObj);
        CCSEC_LOG_INFO("GetUserData" << &getUserData);

        SCF_Close(m_clientObj);
        SCF_FreeCert(certCtx);
        SCF_FreePolicyCtx(m_client);
        SCF_FreePolicyObj(m_clientObj);
        SCF_FreePolicyCtx(m_server);
        SCF_FreePolicyObj(m_serverObj);
        count++;
        CCSEC_LOG_INFO("count " << count);
        delete m_client_conn;
        m_client_conn = nullptr;
    }
    DT_FUZZ_END()
    printf("------TestConn Cert end------\n");
}
}
#pragma GCC diagnostic pop