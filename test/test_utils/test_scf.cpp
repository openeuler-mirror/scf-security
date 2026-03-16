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

#include "test_scf.h" // test

#include <custom_logger.h>
#include <linux/limits.h>

#include <cstdio>
#include <filesystem>

#include "scf.h"
#include "scf_errno.h" // scf
#include "scf_ssl.h"

#define TEST_MAXLOOPS 1000
#define TEST_REPEAT_LOG_TIME 100 // 重复日志抑制倍数，仅在首次和每重复 TEST_REPEAT_LOG_TIME 次时打印

using namespace scf;
namespace test {
// 参考 openssl 的 create_bare_ssl_connection
int Test_CreateBareSslConnection(SCF_PolicyObj *serverssl, SCF_PolicyObj *clientssl, int want)
{
    int retc = -1;
    int rets = -1;
    int err;
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

    return 1;
}

int32_t TEST_PskCreateSession(const uint8_t *psk, size_t pskLen, const void *cipherSuite, SCF_Session **session)
{
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

int32_t TestAddPemCertWithExpected(SCF_PolicyCtx *ctx, const char *filePath, SCF_CERT_TYPE type, int32_t expected)
{
    int32_t ret = SCF_ERROR;
    if (ctx == nullptr || filePath == nullptr) {
        return ret;
    }
    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    EXPECT_NE(fileCtx, nullptr);
    auto *buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(filePath));
    ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, buf, strlen(filePath), SCF_STORE_FORMAT_PEM);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddCert(ctx, fileCtx, type);
    EXPECT_EQ(ret, expected);
    SCF_FileCtxFree(&fileCtx);

    return ret;
}

int32_t TestAddPemCert(SCF_PolicyCtx *ctx, const char *filePath, SCF_CERT_TYPE type)
{
    return TestAddPemCertWithExpected(ctx, filePath, type, SCF_SUCCESS);
}

int32_t TestAddPemPrivKey(SCF_PolicyCtx *ctx, const char *filePath)
{
    int32_t ret = SCF_ERROR;
    if (ctx == nullptr || filePath == nullptr) {
        return ret;
    }
    SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
    EXPECT_NE(fileCtx, nullptr);
    auto *buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(filePath));
    ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, buf, strlen(filePath), SCF_STORE_FORMAT_PEM);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_SetKey(ctx, fileCtx);
    EXPECT_EQ(ret, SCF_SUCCESS);
    SCF_FileCtxFree(&fileCtx);

    return ret;
}

// 基于 hitls 的实现
static int TEST_HiTLSImpl(void *x509ctx, const char *arg)
{
    // storeCtx 是 PSE 的 SEC_PKI_X509_STORE_CTX_S
    (void)x509ctx;
    const auto *crlPath = arg;
    const int checkSuccess = 1; // 允许返回和 openssl 一致的返回值，需要能屏蔽返回值差异
    const int checkFailed = -1;

    if (crlPath != nullptr && strlen(crlPath) != 0) {
        auto *fd = fopen(crlPath, "r");
        if (fd == nullptr) {
            std::cout << "Failed to load cert revocation list = " << crlPath << std::endl;
            return checkFailed;
        }

        (void)fclose(fd);
    }
    return checkSuccess;
}

int32_t TEST_AppVerifyFuncImpl(void *storeCtx, void *arg)
{
    return TEST_HiTLSImpl(storeCtx, static_cast<const char *>(arg));
}

std::string GetLocalPath()
{
    return PROJECT_SOURCE_DIR;
}
}