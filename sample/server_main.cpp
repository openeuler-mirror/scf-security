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

#include <cstdio>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include "securec.h"
#include "test_tcp_server.h"
#include "test_tcp_common.h"
#include "scf.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "scf_ssl.h"
using namespace ::scf;
namespace scf {
enum class TestPskIDType {
    TEST_PSK_ID_MISMATCH,
    TEST_PSK_ID_PLAIN_SHA256,
    TEST_PSK_ID_PLAIN_SHA384
};

static uint16_t g_sslCipherSuite = 0;
uint16_t *g_cipherSuites = nullptr;
size_t g_cipherSuitesLen = 0;
SCF_PolicyCtx *g_server = nullptr;
SCF_PolicyObj *g_serverObj = nullptr;
test::fw::TestTcpConnection *g_conn = nullptr;
constexpr uint32_t RW_LEN = 1024; // 传输的数据大小
constexpr uint32_t DATA_BUF_LEN = 4096;

static uint8_t g_idPskSha256[] = "idPskSha256";
static uint8_t g_idPskSha384[] = "idPskSha384";
constexpr uint32_t ID_LEN = 11;
static uint8_t g_pskPlainSha256[] = "pskPlainSha256";
static uint8_t g_pskPlainSha384[] = "pskPlainSha384";
constexpr uint32_t PSK_LEN = 14;

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

void ServerSslReadWrite(uint32_t rwLen)
{
    int32_t ret = SCF_ERROR;
    uint8_t* dataSW = new uint8_t[DATA_BUF_LEN] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t* dataSR = new uint8_t[DATA_BUF_LEN](); // server read
    uint32_t dataSLen = std::min(DATA_BUF_LEN, rwLen);
    uint32_t writeSLen = 0;
    uint32_t readSLen = 0;

    ret = SCF_Write(g_serverObj, dataSW, dataSLen, &writeSLen);
    if (ret!= SCF_SUCCESS || writeSLen <= 0) {
        std::cout << "SCF_Write error" << ret << std::endl;
    }
    ret = SCFRead(g_serverObj, dataSR, DATA_BUF_LEN, &readSLen);
    if (ret!= SCF_SUCCESS || rwLen!= readSLen) {
        std::cout << "SCFRead error" << ret << std::endl;
    }

    delete[] dataSW;
    delete[] dataSR;
}

// 参考 openssl 的 create_bare_ssl_connection
int CreateServerBareSslConnection(SCF_PolicyObj *serverSSL, int want)
{
    int rets = -1;
    int err = 0;
    int abortCtr = 0;
    int serverErr = 0;

    do {
        err = SCF_SSL_ERR_WANT_WRITE;
        while (!serverErr && rets != SCF_SUCCESS && err == SCF_SSL_ERR_WANT_WRITE) {
            rets = SCF_Accept(serverSSL);
            err = rets;
            if (abortCtr % TEST_REPEAT_LOG_TIME == 0) {
                printf("SSL_accept %d\n", rets);
            }
        }

        if (!serverErr && rets != SCF_SUCCESS && err != SCF_SSL_ERR_WANT_READ) {
            printf("SSL_accept() failed %d, %d\n", rets, err);
            if (want != SCF_ERROR) {
                // 不符合预期
                printf("SSL server not expect\n");
            }
            serverErr = 1; // 实际异常
        }
        if (want != SCF_SUCCESS && err == want) {
            // 符合预期的异常
            printf("want != SCF_SUCCESS && err == want\n");
            return 0;
        }
        if (serverErr) {
            // 不符合预期的异常
            printf("serverErr\n");
            return 0;
        }
        if (++abortCtr == TEST_MAXLOOPS) {
            printf("No progress made\n");
            return 0;
        }
        usleep(TEST_USLEEP_TIME); // 非阻塞的，当前没有用 poll 类的事件机制，因此读太快可能读不到，需要等待一下。
    } while (rets != SCF_SUCCESS);

    return 1;
}

TestPskIDType TEST_SetGetPskAuthType(const uint8_t *identity, uint32_t identityLen)
{
    if (identityLen == ID_LEN) {
        if (memcmp(identity, g_idPskSha256, identityLen) == 0) {
            return TestPskIDType::TEST_PSK_ID_PLAIN_SHA256;
        }
    }

    if (identityLen == ID_LEN) {
        if (memcmp(identity, g_idPskSha384, identityLen) == 0) {
            return TestPskIDType::TEST_PSK_ID_PLAIN_SHA384;
        }
    }
    return TestPskIDType::TEST_PSK_ID_MISMATCH;
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

int32_t TEST_SetPskFindSessionImpl(
    SCF_PolicyObj *obj, const uint8_t *identity, uint32_t identityLen, SCF_Session **session)
{
    if (obj == nullptr || identity == nullptr || identityLen == 0 || session == nullptr) {
        return SCF_ERRNO_NULL_INPUT;
    }

    TestPskIDType pskAuth = TEST_SetGetPskAuthType(identity, identityLen);

    const void *cipherSuite = nullptr;
    uint8_t tls13Aes128GcmSha256Id[] = {0x13, 0x01}; // IANA编码 TLS_AES_128_GCM_SHA256
    uint8_t tls13Aes256GcmSha384Id[] = {0x13, 0x02}; // IANA编码 TLS_AES_256_GCM_SHA384
    uint8_t *psk = nullptr;
    size_t pskLen = 0;
    if (pskAuth == TestPskIDType::TEST_PSK_ID_PLAIN_SHA256) {
        cipherSuite = SCF_CipherFind(obj, tls13Aes128GcmSha256Id);
        psk = g_pskPlainSha256;
        pskLen = PSK_LEN;
    } else if (pskAuth == TestPskIDType::TEST_PSK_ID_PLAIN_SHA384) {
        cipherSuite = SCF_CipherFind(obj, tls13Aes256GcmSha384Id);
        psk = g_pskPlainSha384;
        pskLen = PSK_LEN;
    } else {
        memset_s(tls13Aes128GcmSha256Id, sizeof(tls13Aes128GcmSha256Id), 0, sizeof(tls13Aes128GcmSha256Id));
        memset_s(tls13Aes256GcmSha384Id, sizeof(tls13Aes256GcmSha384Id), 0, sizeof(tls13Aes256GcmSha384Id));
        return SCF_SSL_ERR_PSK_MISMATCH;
    }
    memset_s(tls13Aes128GcmSha256Id, sizeof(tls13Aes128GcmSha256Id), 0, sizeof(tls13Aes128GcmSha256Id));
    memset_s(tls13Aes256GcmSha384Id, sizeof(tls13Aes256GcmSha384Id), 0, sizeof(tls13Aes256GcmSha384Id));
    return TEST_PskCreateSession(psk, pskLen, cipherSuite, session);
}

void FreeGlobalConnAndServerObj()
{
    delete g_conn;
    g_conn = nullptr;
    SCF_FreePolicyObj(&g_serverObj);
    SCF_FreePolicyCtx(&g_server);
}

bool TestServer(char *serverIp, uint16_t port)
{
    int32_t ret = SCF_ERROR;
    ret = SCF_SetCipherSuites(g_server, g_cipherSuites, g_cipherSuitesLen);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetCipherSuites error:" << ret << std::endl;
        return false;
    }
    ret = SCF_SetProtocolVersion(g_server, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, nullptr, 0);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetProtocolVersion error:" << ret << std::endl;
        return false;
    }
    ret = SCF_SetPskFindSessionCallback(g_server, TEST_SetPskFindSessionImpl);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetPskFindSessionCallback error:" << ret << std::endl;
        return false;
    }

    g_serverObj = SCF_CreatePolicyObj(g_server);
    if (g_serverObj == nullptr) {
        std::cout << "SCF_CreatePolicyObj error." << std::endl;
        return false;
    }

    test::fw::TestTcpServer testServer(serverIp, port); // 服务段IP
    ret = testServer.Start();
    if (ret != test::fw::NN_OK) {
        std::cout << "testServer.Connect error:" << ret << std::endl;
        return false;
    }

    int fdServer = testServer.GetAcceptFd();
    if (fdServer < 0) {
        std::cout << "GetAcceptFd error:" << fdServer << std::endl;
        return false;
    }

    // fd 转移给 SCF_PolicyCtx，跟随 SCF_PolicyCtx 的释放关闭，不需要单独关闭
    ret = SCF_SetFd(g_serverObj, fdServer);
    if (ret != SCF_SUCCESS) {
        std::cout << "SCF_SetFd error:" << ret << std::endl;
        return false;
    }

    ret = CreateServerBareSslConnection(g_serverObj, SCF_SUCCESS);
    if (ret != 1) {
        std::cout << "CreateServerBareSslConnection error:" << ret << std::endl;
        return false;
    }
    // 先传输一次，降低首次数据传输影响
    ServerSslReadWrite(RW_LEN);
    int64_t beginTime = test::fw::SystemMicrosecondsGet();
    for (int32_t i = 0; i < TEST_MAXLOOPS; i++) {
        ServerSslReadWrite(RW_LEN);
    }
    int64_t endTime = test::fw::SystemMicrosecondsGet();
    int64_t gapTimeSsl = endTime - beginTime;
    std::cout << "server gapTimeSsl:" << gapTimeSsl << "\n";
    return true;
}

bool InitServer(uint64_t flag, void *settings)
{
    SetExternalLogFunction(test::fw::ExternalLogFunc);
    auto ret = SCF_Init(flag, settings);
    if (ret != SCF_SUCCESS) {
        std::cout << "InitServer SCF_Init error:" << ret << std::endl;
        return false;
    }
    g_server = SCF_CreatePolicyCtx();
    if (g_server == nullptr) {
        std::cout << "InitServer SCF_CreatePolicyCtx error" << std::endl;
        scf::SCF_DeInit();
        return false;
    }
    ret = SCF_SetPolicy(g_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    if (ret != SCF_SUCCESS) {
        std::cout << "InitServer SCF_SetPolicy error:" << ret << std::endl;
        SCF_FreePolicyCtx(&g_server);
        g_server = nullptr;
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
        std::cout << "Invalid Params, example: ./server_main [tlsFlag] [libPath] [serverIp] [port]" << std::endl;
        return 1;
    }
    if (std::string(argv[test::fw::TEST_SSL_FLAG_INDEX]) != "openssl") {
        std::cout << "Invalid Params only openssl supported" << std::endl;
        return 1;
    }
    uint64_t flag = SCF_INIT_FLAG_OPENSSL;
    if (!scf::InitServer(flag, argv[test::fw::TEST_SSL_LIBPATH_INDEX])) {
        std::cout << "TestServer fail" << std::endl;
        return 0;
    }
    // psk 需要指定版本和算法套
    scf::g_sslCipherSuite = SCF_SSL_AES_256_GCM_SHA384;
    uint16_t cipherSuites[] = {
        SCF_SSL_AES_256_GCM_SHA384,
    };
    scf::g_cipherSuites = cipherSuites;
    scf::g_cipherSuitesLen = sizeof(cipherSuites) / sizeof(uint16_t);

    if (scf::TestServer(argv[test::fw::TEST_SSL_IP_INDEX], port)) {
        std::cout << "TestServer success" << std::endl;
    } else {
        std::cout << "TestServer fail" << std::endl;
    }
    FreeGlobalConnAndServerObj();
    SCF_DeInit();
    return 0;
}