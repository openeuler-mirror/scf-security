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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <vector>

#include "securec.h"
#include "test_tcp_client.h"

#include "scf.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "scf_def.h"
#include "test_tcp_common.h"
using namespace ::scf;
namespace scf {
static uint16_t g_sslCipherSuite = 0;
uint16_t *g_cipherSuites = nullptr;
size_t g_cipherSuitesLen = 0;
SCF_PolicyCtx *g_client = nullptr;
SCF_PolicyObj *g_clientObj = nullptr;
test::fw::TestTcpConnection *g_conn = nullptr;
constexpr uint32_t RW_LEN = 1024; // 传输的数据大小
constexpr uint32_t DATA_BUF_LEN = 4096;

static uint8_t g_idPskSha256[] = "idPskSha256";
static uint8_t g_idPskSha384[] = "idPskSha384";
constexpr uint32_t ID_LEN = 11;
static uint8_t g_pskPlainSha256[] = "pskPlainSha256";
static uint8_t g_pskPlainSha384[] = "pskPlainSha384";
constexpr uint32_t PSK_LEN = 14;

int CreateClientBareSslConnection(SCF_PolicyObj *clientSSL, int want)
{
    int retC = -1;
    int err = 0;
    int abortCtr = 0;
    int clientErr = 0;

    if (clientSSL == nullptr) {
        return 0;
    }

    do {
        err = SCF_SSL_ERR_WANT_WRITE;
        // 1. 客户端没有异常；2.建链还没成功；3.建链状态还是 WANT_WRITE
        while (!clientErr && retC != SCF_SUCCESS && err == SCF_SSL_ERR_WANT_WRITE) {
            retC = SCF_Connect(clientSSL);
            err = retC;
            if (abortCtr % TEST_REPEAT_LOG_TIME == 0) {
                printf("SSL_connect %d\n", retC);
            }
        }

        // 判断是实际异常，还是建链等待状态
        if (!clientErr && retC != SCF_SUCCESS && err != SCF_SSL_ERR_WANT_READ) {
            printf("SSL_connect() failed %d, %d\n", retC, err);
            if (want != SCF_ERROR) {
                // 不符合预期
                printf("SSL client not expect\n");
            }
            clientErr = 1; // 实际异常
        }
        if (want != SCF_SUCCESS && err == want) {
            // 符合预期的异常
            printf("want != SCF_SUCCESS && err == want\n");
            return 0;
        }
        if (clientErr) {
            // 不符合预期的异常
            printf("clientErr\n");
            return 0;
        }
        if (++abortCtr == TEST_MAXLOOPS) {
            printf("No progress made\n");
            return 0;
        }
        usleep(TEST_USLEEP_TIME); // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    } while (retC != SCF_SUCCESS);
    return 1;
}

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

void ClientSSLReadWrite(uint32_t rwLen)
{
    static int cnt = 0;
    cnt++;
    int32_t ret = SCF_ERROR;

    uint8_t *dataCW = new uint8_t[DATA_BUF_LEN]{
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    uint8_t *dataCR = new uint8_t[DATA_BUF_LEN]();
    uint32_t dataCLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeCLen = 0;
    uint32_t readCLen = 0;

    ret = SCFRead(g_clientObj, dataCR, DATA_BUF_LEN, &readCLen);
    if (ret != SCF_SUCCESS || rwLen != readCLen) {
        std::cout << "SCFRead error" << ret << std::endl;
    }

    ret = SCF_Write(g_clientObj, dataCW, dataCLen, &writeCLen);
    if (ret != SCF_SUCCESS || writeCLen <= 0) {
        std::cout << "SCF_Write error" << ret << std::endl;
    }

    delete[] dataCW;
    delete[] dataCR;
}

int32_t TEST_PskCreateSession(uint8_t *psk, size_t pskLen, const void *cipherSuite, SCF_Session **session)
{
    if (session == nullptr) {
        return SCF_ERRNO_INVALID_PARAM;
    }
    SCF_Session *sess = SCF_SessionNew();
    if (sess == nullptr) {
        return SCF_ERRNO_MEM_ALLOC;
    }
    // 业务应该需要加密存储 psk，使用时临时解密为明文使用，使用后清理敏感数据
    int32_t ret = SCF_SessionSetMasterKey(sess, psk, pskLen);
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(&sess);
        return ret;
    }
    ret = SCF_SessionSetCipher(sess, cipherSuite, 2); // 当前rfc规定为2
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(&sess);
        return ret;
    }
    // 参考 openssl 自身实现，建议写死。业务上会知道配置使用的 psk 是 1.3 还是 1.2 的。不同版本配置的回调也是不同的。
    ret = SCF_SessionSetProtocolVersion(sess, SCF_SSL_VERSION_TLS13_STR);
    if (ret != SCF_SUCCESS) {
        SCF_SessionFree(&sess);
        return ret;
    }
    *session = sess;
    return ret;
}

int32_t TEST_SetPskUseSessionImpl(
    SCF_PolicyObj *obj, uint32_t hashAlgo, const uint8_t **id, uint32_t *idLen, SCF_Session **session)
{
    int32_t ret = SCF_ERROR;
    if (obj == nullptr || id == nullptr || idLen == nullptr || session == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }
    uint8_t *psk = nullptr;
    size_t pskLen = 0;
    const void *cipherSuite = nullptr;
    uint8_t tls13Aes128GcmSha256Id[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
    uint8_t tls13Aes256GcmSha384Id[] = {0x13, 0x02}; // IANA编码 TLS_AES_256_GCM_SHA384
    if (hashAlgo == SCF_CRYPT_MD_UNKNOWN) {
        // client hello 时会是 0
        hashAlgo = (g_sslCipherSuite == SCF_SSL_AES_256_GCM_SHA384) ? SCF_CRYPT_MD_SHA384 : SCF_CRYPT_MD_SHA256;
    }
    switch (hashAlgo) {
        case SCF_CRYPT_MD_SHA256: {
            /* 用户需要自己保证代码里配置的算法套和这里是匹配的。因为仅 hash 算法参数不能区分
             * TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256 和 TLS_AES_128_CCM_SHA256 */
            cipherSuite = SCF_CipherFind(obj, tls13Aes128GcmSha256Id);
            *id = g_idPskSha256;
            *idLen = ID_LEN;
            pskLen = PSK_LEN;
            psk = g_pskPlainSha256;
            ret = SCF_SUCCESS;
            break;
        }
        case SCF_CRYPT_MD_SHA384: {
            cipherSuite = SCF_CipherFind(obj, tls13Aes256GcmSha384Id);
            *id = g_idPskSha384;
            *idLen = ID_LEN;
            psk = g_pskPlainSha384;
            pskLen = PSK_LEN;
            ret = SCF_SUCCESS;
            break;
        }
        default:
            ret = SCF_SSL_ERR_PSK_CB_HASH;
            break;
    }
    if (ret != SCF_SUCCESS) {
        memset_s(tls13Aes128GcmSha256Id,  sizeof(tls13Aes128GcmSha256Id), 0, sizeof(tls13Aes128GcmSha256Id));
        memset_s(tls13Aes256GcmSha384Id, sizeof(tls13Aes256GcmSha384Id), 0, sizeof(tls13Aes256GcmSha384Id));
        return ret;
    }
    memset_s(tls13Aes128GcmSha256Id, sizeof(tls13Aes128GcmSha256Id), 0, sizeof(tls13Aes128GcmSha256Id));
    memset_s(tls13Aes256GcmSha384Id, sizeof(tls13Aes256GcmSha384Id), 0, sizeof(tls13Aes256GcmSha384Id));
    return TEST_PskCreateSession(psk, pskLen, cipherSuite, session);
}

void FreeGlobalConnAndClientObj()
{
    delete g_conn;
    g_conn = nullptr;
    SCF_FreePolicyObj(&g_clientObj);
    SCF_FreePolicyCtx(&g_client);
}

bool TestClient(char *serverIp, uint16_t port)
{
    auto ret = SCF_SetCipherSuites(g_client, g_cipherSuites, g_cipherSuitesLen);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetCipherSuites error:" << ret << std::endl;
        return false;
    }
    ret = SCF_SetProtocolVersion(g_client, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, nullptr, 0);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetProtocolVersion error:" << ret << std::endl;
        return false;
    }
    ret = SCF_SetPskUseSessionCallback(g_client, TEST_SetPskUseSessionImpl);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetPskUseSessionCallback error:" << ret << std::endl;
        return false;
    }

    g_clientObj = SCF_CreatePolicyObj(g_client);
    if (g_clientObj == nullptr) {
        std::cout << "SCF_CreatePolicyObj error:" << ret << std::endl;
        return false;
    }

    test::fw::TestTcpClient testClient{}; // 客户端ip
    ret = testClient.Connect(serverIp, port, g_conn);   // 服务端ip
    if (ret != test::fw::NN_OK) {
        std::cout << "testClient.Connect error:" << ret << std::endl;
        return false;
    }

    int fdClient = g_conn->GetFd();
    if (fdClient < 0) {
        std::cout << "GetFd error:" << fdClient << std::endl;
        return false;
    }

    ret = SCF_SetFd(g_clientObj, fdClient);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetFd error:" << ret << std::endl;
        return false;
    }

    ret = CreateClientBareSslConnection(g_clientObj, SCF_SUCCESS);
    if (ret != 1) {
        std::cout << "CreateClientBareSslConnection error:" << ret << std::endl;
        return false;
    }
    // 先传输一次，降低首次数据传输影响
    ClientSSLReadWrite(RW_LEN);
    int64_t beginTime = test::fw::SystemMicrosecondsGet();
    for (int32_t i = 0; i < TEST_MAXLOOPS; i++) {
        ClientSSLReadWrite(RW_LEN);
    }
    int64_t endTime = test::fw::SystemMicrosecondsGet();
    int64_t gapTimeSsl = endTime - beginTime;
    std::cout << "client gapTimeSsl:" << gapTimeSsl << "\n";
    return true;
}

bool InitClient(uint64_t flag, void *settings)
{
    SetExternalLogFunction(test::fw::ExternalLogFunc);
    auto ret = SCF_Init(flag, settings);
    if (ret != SCF_SUCCESS) {
        std::cout << "InitServer SCF_Init error:" << ret << std::endl;
        return false;
    }
    g_client = SCF_CreatePolicyCtx();
    if (g_client == nullptr) {
        std::cout << "InitClient SCF_CreatePolicyCtx error" << std::endl;
        scf::SCF_DeInit();
        return false;
    }
    ret = SCF_SetPolicy(g_client, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    if (ret != SCF_SUCCESS) {
        std::cout << "InitClient SCF_SetPolicy error:" << ret << std::endl;
        SCF_FreePolicyCtx(&g_client);
        g_client = nullptr;
        scf::SCF_DeInit();
        return false;
    }
    return true;
}
}

/* 主函数 */
int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
{
    uint16_t port = 0;
    if (argc != test::fw::TEST_SSL_PARAM_COUNT ||
        test::fw::ParsePort(argv[test::fw::TEST_SSL_PORT_INDEX], port) != SCF_SUCCESS) {
        std::cout << "Invalid Params, example: ./client_main [tlsFlag] [libPath] [serverIp] [port]" << std::endl;
        return 1;
    }
    if (std::string(argv[1]) != "openssl") {
        std::cout << "Invalid Params only openssl supported" << std::endl;
        return 1;
    }
    uint64_t flag = SCF_INIT_FLAG_OPENSSL;
    if (!scf::InitClient(flag, argv[test::fw::TEST_SSL_LIBPATH_INDEX])) {
        std::cout << "TestClient fail" << std::endl;
        return 0;
    }
    // psk 需要指定版本和算法套
    scf::g_sslCipherSuite = SCF_SSL_AES_256_GCM_SHA384;
    uint16_t cipherSuites[] = {
        SCF_SSL_AES_256_GCM_SHA384,
    };
    scf::g_cipherSuites = cipherSuites;
    scf::g_cipherSuitesLen = sizeof(cipherSuites) / sizeof(uint16_t);

    if (scf::TestClient(argv[test::fw::TEST_SSL_IP_INDEX], port)) {
        std::cout << "TestClient success" << std::endl;
    } else {
        std::cout << "TestClient fail" << std::endl;
    }

    FreeGlobalConnAndClientObj();
    scf::SCF_DeInit();
    return 0;
}