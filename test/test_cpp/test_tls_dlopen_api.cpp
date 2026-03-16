// Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
// Secure Communication Framework is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#include <dlfcn.h>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <unistd.h>

#include <climits>
#include <cstring>
#include <filesystem>

#include "custom_logger.h"
#include "securec.h"

#include "scf.h"
#include "scf_def.h"
#include "scf_errno.h"
#include "scf_ssl.h"
#include "test_scf.h"

using namespace scf;

#define DLSYM(handle, type, ptr, sym)                                           \
    do {                                                                        \
        auto ptr1 = dlsym((handle), (sym));                                     \
        if (ptr1 == nullptr) {                                                  \
            CCSEC_LOG_ERROR("|load sym|END|returnF||Failed to load " << (sym)); \
            return -1;                                                          \
        }                                                                       \
        (ptr) = (type)ptr1;                                                     \
    } while (0)

namespace test {
using FuncExternalLogFuction = void (*)(int level, const char *msg);
using FuncSetExternalLogFuction = void (*)(FuncExternalLogFuction func);
using FuncSCFFileCtxNew = SCF_FILE_CTX *(*)(void);
using FuncSCFFileCtxFree = void (*)(SCF_FILE_CTX **ctx);
using FuncSCFInit = int32_t (*)(uint64_t flag, void *settings);
using FuncSCFDeInit = void (*)(void);
using FuncSCFFileCtxSetBuf = int32_t (*)(
    SCF_FILE_CTX *ctx, SCF_STORE_TYPE storeType, uint8_t *buf, size_t bufLen, SCF_STORE_FORMAT format);
using FuncSCFFileCtxSetPwd = int32_t (*)(SCF_FILE_CTX *ctx, uint8_t *passwd, size_t passwdLen, bool isCipher);
using FuncSCFCreatePolicyCtx = SCF_PolicyCtx *(*)(void);
using FuncSCFFreePolicyCtx = void (*)(SCF_PolicyCtx **ctx);
using FuncSCFCreatePolicyObj = SCF_PolicyObj *(*)(SCF_PolicyCtx *ctx);
using FuncSCFFreePolicyObj = void (*)(SCF_PolicyObj **obj);
using FuncSCFClose = int32_t (*)(SCF_PolicyObj *obj);
using FuncSCFSetPolicy = int32_t (*)(
    SCF_PolicyCtx *ctx, SCF_ROLE role, SCF_VERIFY_MODE verifyMode, SCF_POLICY_MODE policyMode);
using FuncSCFAddCert = int32_t (*)(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type);
using FuncSCFSetConfigFile = int32_t (*)(
    SCF_PolicyCtx *ctx, SCF_STORE_TYPE type, const char *config, size_t configLen);
using FuncSCFSetFd = int32_t (*)(SCF_PolicyObj *obj, int32_t fd);
using FuncSCFSetCipherSuites = int32_t (*)(
    SCF_PolicyCtx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize);
using FuncSCFSetProtocolVersion = int32_t (*)(
    SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion, uint32_t *forbidVersion, uint32_t forbidVersionLen);
using FuncSCFSessionNew = SCF_Session *(*)(void);
using FuncSCFSessionSetMasterKey = int32_t (*)(SCF_Session *sess, const uint8_t *in, size_t len, bool isCipher);
using FuncSCFSessionSetCipher = int32_t (*)(SCF_Session *sess, const void *cipherSuite, size_t cipherLen);
using FuncSCFSessionSetProtocolVersion = int32_t (*)(SCF_Session *sess, const char *version);
using FuncSCFSessionFree = void (*)(SCF_Session **sess);
using FuncSCFConnect = int32_t (*)(SCF_PolicyObj *obj);
using FuncSCFAccept = int32_t (*)(SCF_PolicyObj *obj);
using FuncSCFRead = int32_t (*)(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen);
using FuncSCFWrite = int32_t (*)(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen);
using FuncSCFSetKey = int32_t (*)(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx);
using FuncSCFSetAppVerifyCallback = int32_t (*)(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg);
using FuncSCFGetProtocolVersion = const char *(*)(SCF_PolicyObj *obj);
using FuncSCFCheckPrivateKey = int32_t (*)(SCF_PolicyCtx *ctx);
using FuncSCFSetPskFindSessionCallback = int32_t (*)(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb);
using FuncSCFSetPskUseSessionCallback = int32_t (*)(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb);
using FuncSCFGetFd = int32_t (*)(SCF_PolicyObj *obj);
using FuncSCFGetCertVersion = int32_t (*)(const void *cert);
using FuncSCFGetCertStartTime = int32_t (*)(const void *cert, char *certStartTimeBuffer, const int bufferLen);
using FuncSCFGetCertEndTime = int32_t (*)(const void *cert, char *certEndTimeBuffer, const int bufferLen);
using FuncSCFGetCipherSuites = int32_t (*)(
    SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen, uint32_t *cipherSuitesSize);
using FunSCFCipherFind = const void *(*)(SCF_PolicyObj *obj, uint8_t *cipherId);
using FunSCFGetPeerCert = const void *(*)(SCF_PolicyObj *obj);
using FunSCFGetCertSerialNumber = uint8_t *(*)(const void *cert, uint32_t *dataLen);
using FuncSCFGetCurrentCert = const void *(*)(SCF_PolicyObj *obj);
using FuncSCFSetKeyAutoUpdateParam = int32_t (*)(
    SCF_PolicyCtx *ctx, bool isNeedKeyUpdate, uint32_t keyUpdateTime, uint64_t keyUpdateTraffic);
using FuncSCFObjKeyUpdate = int32_t (*)(SCF_PolicyObj *obj);
using FuncSCFGetSessionKey = int32_t (*)(SCF_PolicyObj *obj, uint8_t **key, size_t *keyLen);

FuncSCFFileCtxNew g_scfFileCtxNewPtr = nullptr;
FuncSetExternalLogFuction g_scfSetExtenalLogPtr = nullptr;
FuncSCFFileCtxFree g_scfFileCtxFreePtr = nullptr;
FuncSCFInit g_scfInitializedPtr = nullptr;
FuncSCFDeInit g_scfDeInitPtr = nullptr;
FuncSCFFileCtxSetBuf g_scfFileCtxSetBufPtr = nullptr;
FuncSCFFileCtxSetPwd g_scfFileCtxSetPwdPtr = nullptr;
FuncSCFCreatePolicyCtx g_scfCreatePolicyCtxPtr = nullptr;
FuncSCFFreePolicyCtx g_scfFreePolicyCtxPtr = nullptr;
FuncSCFCreatePolicyObj g_scfCreatePolicyObjPtr = nullptr;
FuncSCFFreePolicyObj g_scfFreePolicyObjPtr = nullptr;
FuncSCFConnect g_scfConnectPtr = nullptr;
FuncSCFAccept g_scfAcceptPtr = nullptr;
FuncSCFClose g_scfClosePtr = nullptr;
FuncSCFRead g_scfReadPtr = nullptr;
FuncSCFWrite g_scfWritePtr = nullptr;
FuncSCFSetPolicy g_scfSetPolicyPtr = nullptr;
FuncSCFAddCert g_scfAddCertPtr = nullptr;
FuncSCFSetKey g_scfSetKeyPtr = nullptr;
FuncSCFSetConfigFile g_scfSetConfigFilePtr = nullptr;
FuncSCFSetFd g_scfSetFdPtr = nullptr;
FuncSCFSetAppVerifyCallback g_scfSetAppVerifyCallbackPtr = nullptr;
FuncSCFGetProtocolVersion g_scfGetProtocolVersionPtr = nullptr;
FuncSCFCheckPrivateKey g_scfCheckPrivateKeyPtr = nullptr;
FuncSCFSetCipherSuites g_scfSetCipherSuitesPtr = nullptr;
FuncSCFSetProtocolVersion g_scfSetProtocolVersionPtr = nullptr;
FuncSCFSetPskFindSessionCallback g_scfSetPskFindSessionCallbackPtr = nullptr;
FuncSCFSetPskUseSessionCallback g_scfSetPskUseSessionCallbackPtr = nullptr;
FuncSCFSessionNew g_scfSessionNewPtr = nullptr;
FuncSCFSessionSetMasterKey g_scfSessionSetMasterKeyPtr = nullptr;
FuncSCFSessionSetCipher g_scfSessionSetCipherPtr = nullptr;
FuncSCFSessionSetProtocolVersion g_scfSessionSetProtocolVersionPtr = nullptr;
FuncSCFSessionFree g_scfSessionFreePtr = nullptr;
FuncSCFGetFd g_scfGetFdPtr = nullptr;
FuncSCFGetCertVersion g_scfGetCertVersionPtr = nullptr;
FuncSCFGetCertStartTime g_scfGetCertStartTimePtr = nullptr;
FuncSCFGetCertEndTime g_scfGetCertEndTimePtr = nullptr;
FuncSCFGetCipherSuites g_scfGetCipherSuitesPtr = nullptr;
FunSCFCipherFind g_scfCipherFindPtr = nullptr;
FunSCFGetPeerCert g_scfGetPeerCertPtr = nullptr;
FunSCFGetCertSerialNumber g_scfGetCertSerialNumberPtr = nullptr;
FuncSCFGetCurrentCert g_scfGetCurrentCertPtr = nullptr;
FuncSCFSetKeyAutoUpdateParam g_scfSetKeyAutoUpdateParamPtr = nullptr;
FuncSCFObjKeyUpdate g_funcSCFObjKeyUpdatePtr = nullptr;
FuncSCFGetSessionKey g_funcSCFGetSessionKeyPtr = nullptr;

char g_caFilePath[PATH_MAX];
char g_configfilePath[PATH_MAX];

class TestTlsDlopenApi : public ::testing::Test {
public:
    static int LoadLibSymbols();
    static void UnLoadLibSymbols();
    static int LoadAPI(const std::string &libPath);

protected:
    static void SetUpTestSuite()
    {
        setenv("CCSEC_LOG_LEVEL", "debug", 1);
        std::string libPath = test::GetLocalPath() + "/output/scf/lib64/libscf.so";
        std::string filePath = test::GetLocalPath() + "/test/test_data/certificate/test_cert/ca.pem";
        if (realpath(filePath.c_str(), g_caFilePath) == nullptr) {
            CCSEC_LOG_ERROR("|get ca file path|||file path is:" << filePath << "|Get ca file path failed.");
        }
        std::string configfile = test::GetLocalPath() + "/test/test_data/configfile.json";
        if (realpath(configfile.c_str(), g_configfilePath) == nullptr) {
            CCSEC_LOG_ERROR("|get config file path|||file path is:" << filePath << "|Get config file path failed.");
        }
        ASSERT_EQ(LoadAPI(libPath), 0);
        g_scfSetExtenalLogPtr(ExternalLogFunction);
        std::string setting = "/usr/lib64";
        int32_t ret = g_scfInitializedPtr(SCF_INIT_FLAG_OPENSSL, const_cast<char *>(setting.c_str()));
        ASSERT_EQ(ret, SCF_SUCCESS);
    }

    static void TearDownTestSuite()
    {
        EXPECT_NE(g_scfDeInitPtr, nullptr);
        g_scfDeInitPtr();
        UnLoadLibSymbols();
        if (libHandle != nullptr) {
            dlclose(libHandle);
            libHandle = nullptr;
        }
        gLoaded = false;
    }

private:
    static bool gLoaded;
    static void *libHandle;
};

bool TestTlsDlopenApi::gLoaded = false;
void *TestTlsDlopenApi::libHandle = nullptr;

int TestTlsDlopenApi::LoadLibSymbols()
{
    DLSYM(libHandle, FuncSCFFileCtxNew, g_scfFileCtxNewPtr, "SCF_FileCtxNew");
    DLSYM(libHandle, FuncSetExternalLogFuction, g_scfSetExtenalLogPtr, "SetExternalLogFunction");
    DLSYM(libHandle, FuncSCFFileCtxFree, g_scfFileCtxFreePtr, "SCF_FileCtxFree");
    DLSYM(libHandle, FuncSCFInit, g_scfInitializedPtr, "SCF_Init");
    DLSYM(libHandle, FuncSCFDeInit, g_scfDeInitPtr, "SCF_DeInit");
    DLSYM(libHandle, FuncSCFFileCtxSetBuf, g_scfFileCtxSetBufPtr, "SCF_FileCtxSetBuf");
    DLSYM(libHandle, FuncSCFFileCtxSetPwd, g_scfFileCtxSetPwdPtr, "SCF_FileCtxSetPwd");
    DLSYM(libHandle, FuncSCFCreatePolicyCtx, g_scfCreatePolicyCtxPtr, "SCF_CreatePolicyCtx");
    DLSYM(libHandle, FuncSCFFreePolicyCtx, g_scfFreePolicyCtxPtr, "SCF_FreePolicyCtx");
    DLSYM(libHandle, FuncSCFCreatePolicyObj, g_scfCreatePolicyObjPtr, "SCF_CreatePolicyObj");
    DLSYM(libHandle, FuncSCFFreePolicyObj, g_scfFreePolicyObjPtr, "SCF_FreePolicyObj");
    DLSYM(libHandle, FuncSCFConnect, g_scfConnectPtr, "SCF_Connect");
    DLSYM(libHandle, FuncSCFAccept, g_scfAcceptPtr, "SCF_Accept");
    DLSYM(libHandle, FuncSCFClose, g_scfClosePtr, "SCF_Close");
    DLSYM(libHandle, FuncSCFRead, g_scfReadPtr, "SCF_Read");
    DLSYM(libHandle, FuncSCFWrite, g_scfWritePtr, "SCF_Write");
    DLSYM(libHandle, FuncSCFSetPolicy, g_scfSetPolicyPtr, "SCF_SetPolicy");
    DLSYM(libHandle, FuncSCFAddCert, g_scfAddCertPtr, "SCF_AddCert");
    DLSYM(libHandle, FuncSCFSetKey, g_scfSetKeyPtr, "SCF_SetKey");
    DLSYM(libHandle, FuncSCFSetFd, g_scfSetFdPtr, "SCF_SetFd");
    DLSYM(libHandle, FuncSCFSetAppVerifyCallback, g_scfSetAppVerifyCallbackPtr, "SCF_SetAppVerifyCallback");
    DLSYM(libHandle, FuncSCFGetProtocolVersion, g_scfGetProtocolVersionPtr, "SCF_GetProtocolVersion");
    DLSYM(libHandle, FuncSCFCheckPrivateKey, g_scfCheckPrivateKeyPtr, "SCF_CheckPrivateKey");
    DLSYM(libHandle, FuncSCFSetCipherSuites, g_scfSetCipherSuitesPtr, "SCF_SetCipherSuites");
    DLSYM(libHandle, FuncSCFSetProtocolVersion, g_scfSetProtocolVersionPtr, "SCF_SetProtocolVersion");
    DLSYM(libHandle, FuncSCFSetPskFindSessionCallback, g_scfSetPskFindSessionCallbackPtr,
        "SCF_SetPskFindSessionCallback");
    DLSYM(libHandle, FuncSCFSetPskUseSessionCallback, g_scfSetPskUseSessionCallbackPtr,
        "SCF_SetPskUseSessionCallback");
    DLSYM(libHandle, FuncSCFSessionNew, g_scfSessionNewPtr, "SCF_SessionNew");
    DLSYM(libHandle, FuncSCFSessionSetMasterKey, g_scfSessionSetMasterKeyPtr, "SCF_SessionSetMasterKey");
    DLSYM(libHandle, FuncSCFSessionSetCipher, g_scfSessionSetCipherPtr, "SCF_SessionSetCipher");
    DLSYM(libHandle, FuncSCFSessionSetProtocolVersion, g_scfSessionSetProtocolVersionPtr,
        "SCF_SessionSetProtocolVersion");
    DLSYM(libHandle, FuncSCFSessionFree, g_scfSessionFreePtr, "SCF_SessionFree");
    DLSYM(libHandle, FuncSCFGetCertVersion, g_scfGetCertVersionPtr, "SCF_GetCertVersion");
    DLSYM(libHandle, FuncSCFGetCertStartTime, g_scfGetCertStartTimePtr, "SCF_GetCertStartTime");
    DLSYM(libHandle, FuncSCFGetCertEndTime, g_scfGetCertEndTimePtr, "SCF_GetCertEndTime");
    DLSYM(libHandle, FuncSCFGetCipherSuites, g_scfGetCipherSuitesPtr, "SCF_GetCipherSuites");
    DLSYM(libHandle, FunSCFCipherFind, g_scfCipherFindPtr, "SCF_CipherFind");
    DLSYM(libHandle, FunSCFGetPeerCert, g_scfGetPeerCertPtr, "SCF_GetPeerCert");
    DLSYM(libHandle, FunSCFGetCertSerialNumber, g_scfGetCertSerialNumberPtr, "SCF_GetCertSerialNumber");
    DLSYM(libHandle, FuncSCFGetCurrentCert, g_scfGetCurrentCertPtr, "SCF_GetCurrentCert");
    DLSYM(libHandle, FuncSCFObjKeyUpdate, g_funcSCFObjKeyUpdatePtr, "SCF_ObjKeyUpdate");
    return 0;
}

void TestTlsDlopenApi::UnLoadLibSymbols()
{
    g_scfSetExtenalLogPtr = nullptr;
    g_scfFileCtxNewPtr = nullptr;
    g_scfFileCtxFreePtr = nullptr;
    g_scfInitializedPtr = nullptr;
    g_scfDeInitPtr = nullptr;
    g_scfFileCtxSetBufPtr = nullptr;
    g_scfFileCtxSetPwdPtr = nullptr;
    g_scfCreatePolicyCtxPtr = nullptr;
    g_scfFreePolicyCtxPtr = nullptr;
    g_scfCreatePolicyObjPtr = nullptr;
    g_scfFreePolicyObjPtr = nullptr;
    g_scfConnectPtr = nullptr;
    g_scfAcceptPtr = nullptr;
    g_scfClosePtr = nullptr;
    g_scfReadPtr = nullptr;
    g_scfWritePtr = nullptr;
    g_scfSetPolicyPtr = nullptr;
    g_scfAddCertPtr = nullptr;
    g_scfSetKeyPtr = nullptr;
    g_scfSetFdPtr = nullptr;
    g_scfSetAppVerifyCallbackPtr = nullptr;
    g_scfGetProtocolVersionPtr = nullptr;
    g_scfCheckPrivateKeyPtr = nullptr;
    g_scfSetCipherSuitesPtr = nullptr;
    g_scfSetProtocolVersionPtr = nullptr;
    g_scfSetPskFindSessionCallbackPtr = nullptr;
    g_scfSetPskUseSessionCallbackPtr = nullptr;
    g_scfSessionNewPtr = nullptr;
    g_scfSessionSetMasterKeyPtr = nullptr;
    g_scfSessionSetCipherPtr = nullptr;
    g_scfSessionSetProtocolVersionPtr = nullptr;
    g_scfSessionFreePtr = nullptr;
    g_scfGetCertVersionPtr = nullptr;
    g_scfGetCertStartTimePtr = nullptr;
    g_scfGetCertEndTimePtr = nullptr;
    g_scfGetCipherSuitesPtr = nullptr;
    g_scfCipherFindPtr = nullptr;
    g_scfGetPeerCertPtr = nullptr;
    g_scfGetCertSerialNumberPtr = nullptr;
    g_scfGetCurrentCertPtr = nullptr;
    g_funcSCFObjKeyUpdatePtr = nullptr;
}

int TestTlsDlopenApi::LoadAPI(const std::string &libPath)
{
    if (gLoaded) {
        return 0;
    }

    libHandle = dlopen(libPath.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (libHandle == nullptr) {
        CCSEC_LOG_ERROR("|dlopen|END|returnF||Failed to dlopen " << libPath << ", err:" << dlerror());
        return -1;
    }

    if (LoadLibSymbols() == -1) {
        dlclose(libHandle);
        return -1;
    }

    gLoaded = true;
    return 0;
}

TEST_F(TestTlsDlopenApi, SCF_FileCtxNew_FileCtxFree)
{
    EXPECT_NE(g_scfFileCtxNewPtr, nullptr);
    SCF_FILE_CTX *tmpPtr = g_scfFileCtxNewPtr();
    ASSERT_TRUE(tmpPtr != nullptr);
    EXPECT_NE(g_scfFileCtxFreePtr, nullptr);
    g_scfFileCtxFreePtr(&tmpPtr);
}

TEST_F(TestTlsDlopenApi, TestFileCtxSetPwd)
{
    ASSERT_NE(g_scfFileCtxNewPtr, nullptr);
    SCF_FILE_CTX *tmpPtr = g_scfFileCtxNewPtr();
    EXPECT_NE(tmpPtr, nullptr);
    EXPECT_NE(g_scfFileCtxSetPwdPtr, nullptr);
    std::string pString = "newpasswd";
    size_t pStringLen = pString.size();
    char *passwd = new char[pStringLen + 1];
    (void)strcpy_s(passwd, pStringLen + 1, pString.c_str());
    passwd[pStringLen] = '\0';
    int32_t ret = g_scfFileCtxSetPwdPtr(tmpPtr, reinterpret_cast<uint8_t *>(passwd), pStringLen, false);
    (void)memset_s(passwd, sizeof(passwd), 0, sizeof(passwd));
    delete[] passwd;
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_NE(g_scfFileCtxFreePtr, nullptr);
    g_scfFileCtxFreePtr(&tmpPtr);
}

TEST_F(TestTlsDlopenApi, TestPolicyCtx)
{
    ASSERT_NE(g_scfFileCtxNewPtr, nullptr);
    SCF_FILE_CTX *tmpPtr = g_scfFileCtxNewPtr();
    ASSERT_TRUE(tmpPtr != nullptr);
    ASSERT_NE(g_scfCreatePolicyCtxPtr, nullptr);
    SCF_PolicyCtx *policyctx = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(policyctx != nullptr);

    ASSERT_NE(g_scfSetPolicyPtr, nullptr);
    int32_t ret = g_scfSetPolicyPtr(policyctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_CUSTOMER);
    ASSERT_EQ(ret, SCF_SUCCESS);

    ASSERT_NE(g_scfCreatePolicyObjPtr, nullptr);
    SCF_PolicyObj *obj = g_scfCreatePolicyObjPtr(policyctx);
    ASSERT_TRUE(obj != nullptr);

    ASSERT_NE(g_scfFileCtxSetBufPtr, nullptr);
    auto *caFilePath = reinterpret_cast<uint8_t *>(g_caFilePath);
    ret = g_scfFileCtxSetBufPtr(tmpPtr, SCF_STORE_FILE_PATH, caFilePath, strlen(g_caFilePath),
        SCF_STORE_FORMAT_PEM);
    ASSERT_EQ(ret, SCF_SUCCESS);

    ASSERT_NE(g_scfSetFdPtr, nullptr);
    ret = g_scfSetFdPtr(obj, 0);
    ASSERT_EQ(ret, SCF_SUCCESS);

    uint16_t cipherSuites[] = {SCF_SSL_AES_256_GCM_SHA384};
    ret = g_scfSetCipherSuitesPtr(policyctx, cipherSuites, sizeof(cipherSuites) / sizeof(uint16_t));
    ASSERT_EQ(ret, SCF_SUCCESS);

    ASSERT_NE(g_scfSetProtocolVersionPtr, nullptr);
    ret = g_scfSetProtocolVersionPtr(policyctx, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, NULL, 0);
    ASSERT_EQ(ret, SCF_SUCCESS);

    ASSERT_NE(g_scfFreePolicyObjPtr, nullptr);
    g_scfFreePolicyObjPtr(&obj);
    ASSERT_NE(g_scfFreePolicyCtxPtr, nullptr);
    g_scfFreePolicyCtxPtr(&policyctx);
    ASSERT_NE(g_scfFileCtxFreePtr, nullptr);
    g_scfFileCtxFreePtr(&tmpPtr);
}

TEST_F(TestTlsDlopenApi, SCF_SessionNew_SessionFree)
{
    EXPECT_NE(g_scfSessionNewPtr, nullptr);
    SCF_Session *sessionnew = g_scfSessionNewPtr();
    ASSERT_TRUE(sessionnew != nullptr);
    EXPECT_NE(g_scfSessionFreePtr, nullptr);
    g_scfSessionFreePtr(&sessionnew);
}

TEST_F(TestTlsDlopenApi, SCF_SessionSetMasterKey)
{
    EXPECT_NE(g_scfSessionNewPtr, nullptr);
    SCF_Session *sessionnew = g_scfSessionNewPtr();
    ASSERT_TRUE(sessionnew != nullptr);
    EXPECT_NE(g_scfSessionSetMasterKeyPtr, nullptr);
    const char *pskPlainShA256 = "pskPlainSha256";
    int32_t ret = g_scfSessionSetMasterKeyPtr(
        sessionnew, (const uint8_t *)pskPlainShA256, strlen(pskPlainShA256), false);
    ASSERT_EQ(ret, SCF_SUCCESS);
    EXPECT_NE(g_scfSessionFreePtr, nullptr);
    g_scfSessionFreePtr(&sessionnew);
}

TEST_F(TestTlsDlopenApi, SCF_SessionSetCipher)
{
    EXPECT_NE(g_scfSessionNewPtr, nullptr);
    SCF_Session *sessionnew = g_scfSessionNewPtr();
    ASSERT_TRUE(sessionnew != nullptr);
    EXPECT_NE(g_scfSessionSetCipherPtr, nullptr);
    uint16_t cipherSuites = SCF_SSL_AES_128_GCM_SHA256;
    int32_t ret = g_scfSessionSetCipherPtr(sessionnew, &cipherSuites, 2);
    ASSERT_EQ(ret, SCF_SUCCESS);
    EXPECT_NE(g_scfSessionFreePtr, nullptr);
    g_scfSessionFreePtr(&sessionnew);
}

TEST_F(TestTlsDlopenApi, SCF_SessionSetProtocolVersion)
{
    EXPECT_NE(g_scfSessionNewPtr, nullptr);
    SCF_Session *sessionnew = g_scfSessionNewPtr();
    ASSERT_TRUE(sessionnew != nullptr);
    EXPECT_NE(g_scfSessionSetProtocolVersionPtr, nullptr);
    int32_t ret = g_scfSessionSetProtocolVersionPtr(sessionnew, SCF_SSL_VERSION_TLS13_STR);
    ASSERT_EQ(ret, SCF_SUCCESS);
    EXPECT_NE(g_scfSessionFreePtr, nullptr);
    g_scfSessionFreePtr(&sessionnew);
}

TEST_F(TestTlsDlopenApi, SCF_GetCertVersion)
{
    void *cert = nullptr;
    int32_t ret = g_scfGetCertVersionPtr(cert);
    ASSERT_EQ(ret, -1);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsDlopenApi, SCF_GetCertStartTime)
{
    void *cert = nullptr;
    char certTimeBuffer[100]; // 100 buffer length
    int length = 100;         // 100 buffer length
    auto ret = g_scfGetCertStartTimePtr(cert, certTimeBuffer, length);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsDlopenApi, SCF_GetCertEndTime)
{
    void *cert = nullptr;
    char certTimeBuffer[100]; // 100 buffer length
    int length = 100;         // 100 buffer length
    auto ret = g_scfGetCertEndTimePtr(cert, certTimeBuffer, length);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_FreeCert(&cert);
}

TEST_F(TestTlsDlopenApi, SCF_GetCipherSuites)
{
    EXPECT_NE(g_scfCreatePolicyCtxPtr, nullptr);
    SCF_PolicyCtx *policyctx = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(policyctx != nullptr);
    uint16_t data[1024];
    uint32_t *cipherSuitesSize = nullptr;
    EXPECT_NE(g_scfGetCipherSuitesPtr, nullptr);
    int32_t ret = g_scfGetCipherSuitesPtr(policyctx, data, 1024, cipherSuitesSize);
    ASSERT_TRUE(ret > 0); // 接口未联通
    EXPECT_NE(g_scfFreePolicyCtxPtr, nullptr);
    g_scfFreePolicyCtxPtr(&policyctx);
}

/**
 * API 异常入参测试
 */
TEST_F(TestTlsDlopenApi, UT_API_SCF_SetPolicy_TC001)
{
    int32_t ret = g_scfSetPolicyPtr(nullptr, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_ERRNO_INVALID_PARAM);

    SCF_PolicyCtx *m_server = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(m_server != nullptr);
    ret = g_scfSetPolicyPtr(m_server, SCF_ROLE_NONE, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_ERRNO_INVALID_PARAM);
    SCF_ROLE maxRole = (SCF_ROLE)(SCF_ROLE_SERVER + 1);
    ret = g_scfSetPolicyPtr(m_server, maxRole, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_ERRNO_INVALID_PARAM);

    SCF_VERIFY_MODE errMode = (SCF_VERIFY_MODE)(SCF_VERIFY_FAIL_IF_NO_PEER_CERT + 1);
    ret = g_scfSetPolicyPtr(m_server, SCF_ROLE_SERVER, errMode, SCF_POLICY_HIGH);
    ASSERT_TRUE(ret == SCF_ERRNO_INVALID_PARAM);

    SCF_POLICY_MODE errPolicyMode = SCF_POLICY_MIDDLE;
    ret = g_scfSetPolicyPtr(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, errPolicyMode);
    ASSERT_TRUE(ret == SCF_SUCCESS);
    SCF_FreePolicyCtx(&m_server);
}

TEST_F(TestTlsDlopenApi, UT_API_SCF_AddCert_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *m_server = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(m_server != nullptr);

    SCF_FILE_CTX *fileCtx = g_scfFileCtxNewPtr();
    EXPECT_NE(fileCtx, nullptr);
    ret = g_scfFileCtxSetBufPtr(fileCtx, SCF_STORE_FILE_PATH, (uint8_t *)(uintptr_t)g_caFilePath,
        strlen(g_caFilePath), SCF_STORE_FORMAT_PEM);
    EXPECT_EQ(ret, SCF_SUCCESS);

    ret = g_scfAddCertPtr(nullptr, fileCtx, SCF_CERT_TYPE_CA);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = g_scfAddCertPtr(m_server, nullptr, SCF_CERT_TYPE_CA);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    SCF_CERT_TYPE errCertType = (SCF_CERT_TYPE)(SCF_CERT_TYPE_CRL + 1);
    ret = g_scfAddCertPtr(m_server, fileCtx, errCertType); // 超过最大值的类型
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = g_scfAddCertPtr(m_server, fileCtx, SCF_CERT_TYPE_CA); // 正确的类型，但没有配置策略方式
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    g_scfFileCtxFreePtr(&fileCtx);
    g_scfFreePolicyCtxPtr(&m_server);
}

TEST_F(TestTlsDlopenApi, UT_API_SCF_SetKey_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *m_server = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(m_server != nullptr);

    SCF_FILE_CTX *fileCtx = g_scfFileCtxNewPtr();
    EXPECT_NE(fileCtx, nullptr);
    ret = g_scfFileCtxSetBufPtr(fileCtx, SCF_STORE_FILE_PATH, (uint8_t *)(uintptr_t)g_caFilePath,
        strlen(g_caFilePath), SCF_STORE_FORMAT_PEM);
    EXPECT_EQ(ret, SCF_SUCCESS);

    ret = g_scfSetKeyPtr(nullptr, fileCtx);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = g_scfSetKeyPtr(m_server, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = g_scfSetKeyPtr(m_server, fileCtx); // 正确的类型，但没有配置策略方式
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    g_scfFileCtxFreePtr(&fileCtx);
    g_scfFreePolicyCtxPtr(&m_server);
}

TEST_F(TestTlsDlopenApi, UT_API_SCF_SetFd_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *m_server = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(m_server != nullptr);
    SCF_PolicyObj *obj = g_scfCreatePolicyObjPtr(m_server);
    ASSERT_TRUE(obj != nullptr);

    ret = g_scfSetFdPtr(nullptr, 0);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = g_scfSetFdPtr(obj, -1);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = g_scfSetFdPtr(obj, 1); // 未配置策略类型
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    g_scfFreePolicyCtxPtr(&m_server);
    g_scfFreePolicyObjPtr(&obj);
}

TEST_F(TestTlsDlopenApi, UT_API_SCF_SetProtocolVersion_TC001)
{
    int32_t ret = SCF_ERROR;
    SCF_PolicyCtx *m_server = g_scfCreatePolicyCtxPtr();
    SCF_PolicyCtx *m_client = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(m_server != nullptr);

    ret = g_scfSetProtocolVersionPtr(nullptr, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, NULL, 0);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = g_scfSetProtocolVersionPtr(
        m_client, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS13, NULL, 0); // 未配置策略类型
    ASSERT_EQ(ret, SCF_ERRNO_INVALID_PARAM);

    ret = g_scfSetPolicyPtr(m_server, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);
    ASSERT_EQ(ret, SCF_SUCCESS);

    ret = g_scfSetProtocolVersionPtr(m_server, SCF_SSL_VERSION_TLS12, SCF_SSL_VERSION_TLS13, NULL, 0);
    ASSERT_EQ(ret, SCF_SSL_ERR_POLICY_VERSION);

    ret = g_scfSetProtocolVersionPtr(m_server, SCF_SSL_VERSION_TLS13, SCF_SSL_VERSION_TLS12, NULL, 0);
    ASSERT_EQ(ret, SCF_SSL_ERR_POLICY_VERSION);
    SCF_FreePolicyCtx(&m_server);
    SCF_FreePolicyCtx(&m_client);
}

TEST_F(TestTlsDlopenApi, SCF_ObjKeyUpdate)
{
    SCF_PolicyCtx *m_server = g_scfCreatePolicyCtxPtr();
    ASSERT_TRUE(m_server != nullptr);
    SCF_PolicyObj *policyobj = g_scfCreatePolicyObjPtr(m_server);
    ASSERT_TRUE(policyobj != nullptr);
    int32_t ret = g_funcSCFObjKeyUpdatePtr(nullptr);
    ASSERT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    g_scfFreePolicyObjPtr(&policyobj);
    g_scfFreePolicyCtxPtr(&m_server);
}
}