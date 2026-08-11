/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
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

#include <gtest/gtest.h>
#include <dlfcn.h>
#include <limits>
#include <unistd.h>
#include <vector>
#include "openssl_adaptor.h"
#include "scf.h"
#include "scf_errno.h"
#include "scf_inner.h"
#include "test_scf.h"
#include "securec.h"

using namespace scf;

namespace test {
constexpr size_t NODE_ID_BUFFER_SIZE = 128;
constexpr uint32_t NODE_ROLE_MAP_CAPACITY = 4096;

static AbstractTLSAdaptor **GetLibraryAdaptorSlot()
{
    // 公共 API 位于动态库中，测试必须替换动态库持有的 g_adaptor 才能让 stub 对 API 调用生效。
    static AbstractTLSAdaptor **slot = []() {
        Dl_info libraryInfo{};
        if (dladdr(reinterpret_cast<void *>(SCF_Connect), &libraryInfo) == 0) {
            return static_cast<AbstractTLSAdaptor **>(nullptr);
        }
        void *handle = dlopen(libraryInfo.dli_fname, RTLD_NOW | RTLD_NOLOAD);
        if (handle == nullptr) {
            return static_cast<AbstractTLSAdaptor **>(nullptr);
        }
        return reinterpret_cast<AbstractTLSAdaptor **>(dlsym(handle, "_ZN3scf9g_adaptorE"));
    }();
    return slot;
}

class ConnectionAdaptorStub final : public OpenSSLAdapter {
public:
    int32_t Connect(SCF_PolicyObj *obj) override
    {
        (void)obj;
        return Next(connectResults);
    }

    int32_t Accept(SCF_PolicyObj *obj) override
    {
        (void)obj;
        return Next(acceptResults);
    }

    std::vector<int32_t> connectResults;
    std::vector<int32_t> acceptResults;

private:
    // 按调用顺序返回握手结果，用于模拟 WANT_READ/WANT_WRITE 后建链成功。
    static int32_t Next(std::vector<int32_t> &results)
    {
        if (results.empty()) {
            return SCF_ERROR;
        }
        int32_t ret = results.front();
        results.erase(results.begin());
        return ret;
    }
};

class ScopedAdaptorOverride {
public:
    explicit ScopedAdaptorOverride(AbstractTLSAdaptor *replacement) : previous_(g_adaptor)
    {
        slot_ = GetLibraryAdaptorSlot();
        if (slot_ != nullptr) {
            previous_ = *slot_;
            *slot_ = replacement;
        } else {
            g_adaptor = replacement;
        }
    }

    ~ScopedAdaptorOverride()
    {
        // 每个用例结束后恢复真实 adaptor，避免全局状态污染后续用例。
        if (slot_ != nullptr) {
            *slot_ = previous_;
        } else {
            g_adaptor = previous_;
        }
    }

private:
    AbstractTLSAdaptor **slot_ = nullptr;
    AbstractTLSAdaptor *previous_ = nullptr;
};

class TestRbac : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        ASSERT_EQ(SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath), SCF_SUCCESS);
        ctx_ = SCF_CreatePolicyCtx();
        ASSERT_NE(ctx_, nullptr);
    }

    void TearDown() override
    {
        if (obj_ != nullptr) {
            SCF_FreePolicyObj(&obj_);
        }
        if (ctx_ != nullptr) {
            SCF_FreePolicyCtx(&ctx_);
        }
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }

    void *LoadRbacCert(const char *certName)
    {
        // 证书由 PolicyObj 持有，返回的指针在 TearDown 释放 obj_ 前保持有效。
        EXPECT_EQ(SCF_SetPolicy(ctx_, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH), SCF_SUCCESS);
        std::string certPath = std::string(PROJECT_SOURCE_DIR) + "/test/test_data/certificate/" + certName;
        SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
        EXPECT_NE(fileCtx, nullptr);
        auto *path = reinterpret_cast<uint8_t *>(const_cast<char *>(certPath.c_str()));
        EXPECT_EQ(SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, path, certPath.size(), SCF_STORE_FORMAT_PEM),
            SCF_SUCCESS);
        EXPECT_EQ(SCF_AddCert(ctx_, fileCtx, SCF_CERT_TYPE_EE), SCF_SUCCESS);
        SCF_FileCtxFree(&fileCtx);
        obj_ = SCF_CreatePolicyObj(ctx_);
        EXPECT_NE(obj_, nullptr);
        EXPECT_EQ(SCF_SetFd(obj_, STDOUT_FILENO), SCF_SUCCESS);
        return SCF_GetCurrentCert(obj_);
    }

    SCF_PolicyCtx *ctx_ = nullptr;
    SCF_PolicyObj *obj_ = nullptr;
};

TEST_F(TestRbac, NodeRoleMappingLifecycle)
{
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_MAPPING);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_SLAVE);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, "node-1"), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, &src), SCF_ERRNO_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, "node-1"), SCF_ERRNO_RBAC_MAP_NOT_FOUND);
}

TEST_F(TestRbac, NodeRoleMappingAcceptsBoundaryNodeIdLengths)
{
    const std::string nodeIdLengthOne(1, 'a');
    const std::string nodeIdLength127(127, 'b');

    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, nodeIdLengthOne.c_str(), SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nodeIdLengthOne.c_str()), SCF_SUCCESS);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, nodeIdLength127.c_str(), SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nodeIdLength127.c_str()), SCF_SUCCESS);
}

TEST_F(TestRbac, NodeRoleMappingRejectsInvalidInput)
{
    char unterminatedNodeId[NODE_ID_BUFFER_SIZE];
    char nodeId[2] = {0};
    size_t nodeIdLen = 0;
    char cert = 0;
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    ASSERT_EQ(memset_s(unterminatedNodeId, sizeof(unterminatedNodeId), 'a', sizeof(unterminatedNodeId)), EOK);
    EXPECT_EQ(SCF_SetNodeRoleMapping(nullptr, "node-1", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, nullptr, SCF_RBAC_ROLE_MASTER), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, unterminatedNodeId, SCF_RBAC_ROLE_MASTER), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_UNKNOWN), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", static_cast<SCF_RBAC_ROLE>(3)), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(nullptr, "node-1"), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, unterminatedNodeId), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(nullptr, nullptr, 0, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertNodeId(&cert, nullptr, sizeof(nodeId), &nodeIdLen), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertNodeId(&cert, nodeId, sizeof(nodeId), nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertNodeId(&cert, nodeId, 0, &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertRbacRole(&cert, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertRbacRole(nullptr, &role), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertRbacRole(nullptr, nullptr), SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestRbac, NodeRoleMappingRejectsEntriesBeyondCapacity)
{
    for (uint32_t i = 0; i < NODE_ROLE_MAP_CAPACITY; ++i) {
        std::string nodeId = "node-" + std::to_string(i);
        ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, nodeId.c_str(), SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    }
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-overflow", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_RBAC_MAP_FULL);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-0", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
}

TEST_F(TestRbac, CertificateNodeIdLengthOne)
{
    void *shortCert = LoadRbacCert("rbac_node_id_len_1_cert.pem");
    ASSERT_NE(shortCert, nullptr);
    size_t nodeIdLen = 0;
    char nodeIdBuffer[NODE_ID_BUFFER_SIZE];
    ASSERT_EQ(memset_s(nodeIdBuffer, sizeof(nodeIdBuffer), 'x', sizeof(nodeIdBuffer)), EOK);
    EXPECT_EQ(SCF_GetCertNodeId(shortCert, nodeIdBuffer, 2, &nodeIdLen), SCF_SUCCESS);
    EXPECT_EQ(nodeIdLen, 1U);
    EXPECT_STREQ(nodeIdBuffer, "a");
    EXPECT_EQ(nodeIdBuffer[1], '\0');
}

TEST_F(TestRbac, CertificateNodeIdLength127)
{
    void *maxCert = LoadRbacCert("rbac_node_id_len_127_cert.pem");
    ASSERT_NE(maxCert, nullptr);
    size_t nodeIdLen = 0;
    char nodeIdBuffer[NODE_ID_BUFFER_SIZE];
    ASSERT_EQ(memset_s(nodeIdBuffer, sizeof(nodeIdBuffer), 'x', sizeof(nodeIdBuffer)), EOK);
    EXPECT_EQ(SCF_GetCertNodeId(maxCert, nodeIdBuffer, MAX_NODE_ID_LEN, &nodeIdLen), SCF_SUCCESS);
    EXPECT_EQ(nodeIdLen, MAX_NODE_ID_LEN - 1);
    EXPECT_EQ(std::string(nodeIdBuffer, nodeIdLen), std::string(MAX_NODE_ID_LEN - 1, 'b'));
    EXPECT_EQ(nodeIdBuffer[MAX_NODE_ID_LEN - 1], '\0');
}

TEST_F(TestRbac, CertificateNodeIdLength128IsRejected)
{
    void *overLimitCert = LoadRbacCert("rbac_node_id_len_128_cert.pem");
    ASSERT_NE(overLimitCert, nullptr);
    size_t nodeIdLen = 0;
    char nodeIdBuffer[NODE_ID_BUFFER_SIZE] = {0};
    EXPECT_EQ(SCF_GetCertNodeId(overLimitCert, nodeIdBuffer, MAX_NODE_ID_LEN, &nodeIdLen),
        SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, CertificateNodeIdEmptyIsRejected)
{
    void *cert = LoadRbacCert("rbac_node_id_empty_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeIdBuffer[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, sizeof(nodeIdBuffer), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, NodeRoleMappingIsFrozenOnlyAfterSuccessfulConnect)
{
    ASSERT_EQ(SCF_SetPolicy(ctx_, SCF_ROLE_CLIENT, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH), SCF_SUCCESS);
    obj_ = SCF_CreatePolicyObj(ctx_);
    ASSERT_NE(obj_, nullptr);
    ConnectionAdaptorStub adaptor;
    adaptor.connectResults = {SCF_SSL_ERR_WANT_READ, SCF_SUCCESS};
    ASSERT_NE(GetLibraryAdaptorSlot(), nullptr);
    ScopedAdaptorOverride adaptorOverride(&adaptor);
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_Connect(obj_), SCF_SSL_ERR_WANT_READ);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_Connect(obj_), SCF_SUCCESS);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_RBAC_MAP_FROZEN);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, "node-1"), SCF_ERRNO_RBAC_MAP_FROZEN);
}

TEST_F(TestRbac, NodeRoleMappingIsFrozenOnlyAfterSuccessfulAccept)
{
    ASSERT_EQ(SCF_SetPolicy(ctx_, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH), SCF_SUCCESS);
    obj_ = SCF_CreatePolicyObj(ctx_);
    ASSERT_NE(obj_, nullptr);
    ConnectionAdaptorStub adaptor;
    adaptor.acceptResults = {SCF_SSL_ERR_WANT_WRITE, SCF_SUCCESS};
    ASSERT_NE(GetLibraryAdaptorSlot(), nullptr);
    ScopedAdaptorOverride adaptorOverride(&adaptor);
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_Accept(obj_), SCF_SSL_ERR_WANT_WRITE);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_Accept(obj_), SCF_SUCCESS);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, "node-1"), SCF_ERRNO_RBAC_MAP_FROZEN);
}

TEST_F(TestRbac, RbacSr01ErrorsHaveMessages)
{
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_ROLE_UNKNOWN), "RBAC node role is unknown");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_MAP_FULL), "RBAC node role mapping is full");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_MAP_NOT_FOUND), "RBAC node role mapping is not found");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_CERT_NODE_ID_ABSENT), "RBAC certificate node ID extension is absent");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_CERT_ROLE_EXT_ABSENT), "RBAC certificate role extension is absent");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_MAP_FROZEN), "RBAC node role mapping is frozen");
    EXPECT_STREQ(GetErrorMessage(SCF_SSL_ERR_CERT_EXT_ABSENT), "SSL certificate extension is absent");
}

TEST_F(TestRbac, RbacSr02ErrorsHaveMessages)
{
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_POLICY_NOT_FOUND), "RBAC policy rule is not found");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_POLICY_FULL),
        "RBAC policy rule capacity or ID space is exhausted");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_POLICY_DUPLICATE),
        "RBAC policy rule is duplicated or conflicting");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_POLICY_INVALID), "RBAC policy rule is invalid");
}

TEST_F(TestRbac, NodeRoleMappingRequiresInitializedScf)
{
    SCF_DeInit();
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_NOT_INIT);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, "node-1"), SCF_ERRNO_NOT_INIT);
    char nodeId[2] = {0};
    size_t nodeIdLen = 0;
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    char cert = 0;
    EXPECT_EQ(SCF_GetCertNodeId(&cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_ERRNO_NOT_INIT);
    EXPECT_EQ(SCF_GetCertRbacRole(&cert, &role), SCF_ERRNO_NOT_INIT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, &src), SCF_ERRNO_NOT_INIT);
    char libPath[] = "/usr/lib64";
    ASSERT_EQ(SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath), SCF_SUCCESS);
}

TEST_F(TestRbac, CertificateWithoutRbacExtensionsReturnsUnknownWithoutNodeId)
{
    void *cert = LoadRbacCert("test_cert/client.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_ERRNO_CERT_NODE_ID_ABSENT);
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_ERRNO_CERT_ROLE_EXT_ABSENT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &role, &src), SCF_ERRNO_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(role, SCF_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_NONE);
}

TEST_F(TestRbac, NodeRoleLookupRejectsInvalidInput)
{
    char unterminatedNodeId[NODE_ID_BUFFER_SIZE];
    ASSERT_EQ(memset_s(unterminatedNodeId, sizeof(unterminatedNodeId), 'a', sizeof(unterminatedNodeId)), EOK);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(SCF_GetNodeRbacRole(nullptr, cert, "node-1", &role, &src), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", nullptr, &src), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, nullptr, &role, &src), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "", &role, &src), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, unterminatedNodeId, &role, &src), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestRbac, CertificateExtensionsAndRolePriority)
{
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_SUCCESS);
    EXPECT_STREQ(nodeId, "node-cert");
    EXPECT_EQ(nodeIdLen, 9U);
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-cert", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, "other-node", &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_CERT);
    char smallBuffer[2] = {0};
    char exactBuffer[9] = {0};
    EXPECT_EQ(SCF_GetCertNodeId(cert, smallBuffer, sizeof(smallBuffer), &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(cert, smallBuffer, 1, &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(cert, exactBuffer, sizeof(exactBuffer), &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestRbac, CertificateSlaveRoleIsReturned)
{
    void *cert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_SLAVE);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_SLAVE);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_CERT);
}

TEST_F(TestRbac, CertificateRejectsUnknownRole)
{
    void *cert = LoadRbacCert("rbac_unknown_role_cert.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, CertificateRoleIsCaseInsensitive)
{
    void *cert = LoadRbacCert("rbac_mixed_case_role_cert.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
}

TEST_F(TestRbac, RoleMappingFallbackForCertificateWithoutRoleExtension)
{
    void *cert = LoadRbacCert("rbac_node_only_cert.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_ERRNO_CERT_ROLE_EXT_ABSENT);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-mapped", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_SLAVE);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_MAPPING);
}

TEST_F(TestRbac, CertificateWithoutIdentityUsesCallerNodeId)
{
    void *cert = LoadRbacCert("test_cert/client.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-input", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, "node-input", &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_MAPPING);
}

TEST_F(TestRbac, CertificateNodeIdDoesNotUseCallerNodeId)
{
    void *cert = LoadRbacCert("rbac_node_only_cert.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-input", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, "node-input", &role, &src), SCF_ERRNO_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(role, SCF_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_NONE);
}

TEST_F(TestRbac, CertificateRejectsDuplicateNodeIdExtension)
{
    void *cert = LoadRbacCert("rbac_duplicate_node_id_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &role, &src), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, CertificateRejectsDuplicateRoleExtension)
{
    void *cert = LoadRbacCert("rbac_duplicate_role_cert.pem");
    ASSERT_NE(cert, nullptr);
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    EXPECT_EQ(SCF_GetCertRbacRole(cert, &role), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, CertificateNodeIdRejectsEmbeddedNull)
{
    void *cert = LoadRbacCert("rbac_node_id_embedded_null_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);

    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "admin", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &role, &src), SCF_SSL_ERR_PARSE_CERT);
    EXPECT_EQ(role, SCF_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_NONE);
}

TEST_F(TestRbac, CertificateExtensionRejectsNonCanonicalLongFormLength)
{
    void *cert = LoadRbacCert("rbac_noncanonical_length_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, CertificateExtensionRejectsLeadingZeroLengthOctet)
{
    void *cert = LoadRbacCert("rbac_leading_zero_length_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, CertificateExtensionRejectsInvalidUtf8)
{
    void *cert = LoadRbacCert("rbac_invalid_utf8_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeId[NODE_ID_BUFFER_SIZE] = {0};
    size_t nodeIdLen = 0;
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeId, sizeof(nodeId), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);

    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &role, &src), SCF_SSL_ERR_PARSE_CERT);
    EXPECT_EQ(role, SCF_RBAC_ROLE_UNKNOWN);
    EXPECT_EQ(src, SCF_RBAC_ROLE_SRC_NONE);
}

TEST_F(TestRbac, MasterNodesCanBeListedAndQueried)
{
    char masterNodes[2][MAX_NODE_ID_LEN] = {{0}};
    uint32_t actualCount = 0;
    bool isMaster = false;
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "master-1", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "master-2", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "slave-1", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 1, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 1U);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 2, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);
    EXPECT_EQ(SCF_IsMasterNode(ctx_, "master-1", &isMaster), SCF_SUCCESS);
    EXPECT_TRUE(isMaster);
    EXPECT_EQ(SCF_IsMasterNode(ctx_, "slave-1", &isMaster), SCF_SUCCESS);
    EXPECT_FALSE(isMaster);
    isMaster = true;
    EXPECT_EQ(SCF_IsMasterNode(ctx_, "missing", &isMaster), SCF_ERRNO_RBAC_MAP_NOT_FOUND);
    EXPECT_FALSE(isMaster);
    EXPECT_EQ(SCF_IsMasterNode(ctx_, "", &isMaster), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 0, &actualCount), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestRbac, PolicyRulesSupportCrudAndValidation)
{
    SCF_PolicyRule rules[2];
    uint32_t actualCount = 0;
    uint32_t firstRuleId = 0;
    uint32_t secondRuleId = 0;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &firstRuleId), SCF_SUCCESS);
    EXPECT_NE(firstRuleId, 0U);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "*", SCF_RES_TYPE_ALL, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_DENY, &secondRuleId), SCF_SUCCESS);
    EXPECT_NE(secondRuleId, firstRuleId);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &actualCount), SCF_ERRNO_RBAC_POLICY_DUPLICATE);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 1, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 1U);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 2, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, firstRuleId), SCF_SUCCESS);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, firstRuleId), SCF_ERRNO_RBAC_POLICY_NOT_FOUND);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, 0), SCF_ERRNO_INVALID_PARAM);
    uint32_t removedRuleId = firstRuleId;
    uint32_t readdedRuleId = 0;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &readdedRuleId), SCF_SUCCESS);
    EXPECT_NE(readdedRuleId, removedRuleId);
    EXPECT_GT(readdedRuleId, secondRuleId);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 2, &actualCount), SCF_SUCCESS);
    ASSERT_EQ(actualCount, 2U);
    EXPECT_EQ(rules[0].ruleId, secondRuleId);
    EXPECT_NE(rules[0].ruleId, removedRuleId);
    EXPECT_EQ(rules[0].subjectNodeId, "node-1");
    EXPECT_EQ(rules[0].targetNodeId, "*");
    EXPECT_EQ(rules[0].resourceTypeBitmap, SCF_RES_TYPE_ALL);
    EXPECT_EQ(rules[0].actionBitmap, SCF_RES_ACTION_RELEASE);
    EXPECT_EQ(rules[0].effect, SCF_POLICY_EFFECT_DENY);
    EXPECT_EQ(rules[1].ruleId, readdedRuleId);
    EXPECT_NE(rules[1].ruleId, removedRuleId);
    EXPECT_EQ(rules[1].subjectNodeId, "node-1");
    EXPECT_EQ(rules[1].targetNodeId, "node-2");
    EXPECT_EQ(rules[1].resourceTypeBitmap, SCF_RES_TYPE_FD);
    EXPECT_EQ(rules[1].actionBitmap, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(rules[1].effect, SCF_POLICY_EFFECT_ALLOW);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 0, &actualCount), SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestRbac, AddPolicyRuleRejectsConflictingEffect)
{
    uint32_t ruleId = 0;
    uint32_t conflictingRuleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_DENY, &conflictingRuleId), SCF_ERRNO_RBAC_POLICY_DUPLICATE);
    EXPECT_EQ(conflictingRuleId, 0U);
}

TEST_F(TestRbac, PolicyRuleCapacityRejectsEntryBeyondLimit)
{
    uint32_t ruleId = 0;
    for (uint32_t i = 0; i < MAX_POLICY_RULE_SIZE; ++i) {
        const std::string subjectNodeId = "subject-" + std::to_string(i);
        ASSERT_EQ(SCF_AddPolicyRule(ctx_, subjectNodeId.c_str(), "target", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);
    }
    EXPECT_EQ(ruleId, MAX_POLICY_RULE_SIZE);

    ruleId = 123;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "overflow", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_RBAC_POLICY_FULL);
    EXPECT_EQ(ruleId, 123U);
}

TEST_F(TestRbac, PolicyRuleIdCollisionReturnsIdSpaceError)
{
    uint32_t firstRuleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &firstRuleId), SCF_SUCCESS);
    ctx_->nextPolicyRuleId = firstRuleId;

    uint32_t conflictingRuleId = 123;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-2", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &conflictingRuleId), SCF_ERRNO_RBAC_POLICY_FULL);
    EXPECT_EQ(conflictingRuleId, 123U);
}

TEST_F(TestRbac, PolicyRuleIdExhaustionIsPermanent)
{
    ctx_->nextPolicyRuleId = std::numeric_limits<uint32_t>::max() - 1;
    uint32_t penultimateRuleId = 0;
    uint32_t lastRuleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "penultimate", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &penultimateRuleId), SCF_SUCCESS);
    EXPECT_EQ(penultimateRuleId, std::numeric_limits<uint32_t>::max() - 1);
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "last", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &lastRuleId), SCF_SUCCESS);
    EXPECT_EQ(lastRuleId, std::numeric_limits<uint32_t>::max());
    EXPECT_EQ(ctx_->nextPolicyRuleId, 0U);

    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, lastRuleId), SCF_SUCCESS);
    uint32_t exhaustedRuleId = 123;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "after-exhaustion", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &exhaustedRuleId), SCF_ERRNO_RBAC_POLICY_FULL);
    EXPECT_EQ(exhaustedRuleId, 123U);
}

TEST_F(TestRbac, AddPolicyRuleRejectsEachInvalidField)
{
    char unterminatedNodeId[NODE_ID_BUFFER_SIZE];
    ASSERT_EQ(memset_s(unterminatedNodeId, sizeof(unterminatedNodeId), 'a', sizeof(unterminatedNodeId)), EOK);
    uint32_t ruleId = 123;

    EXPECT_EQ(SCF_AddPolicyRule(nullptr, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(ruleId, 123U);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, nullptr, "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(ruleId, 123U);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", nullptr, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(ruleId, 123U);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, nullptr), SCF_ERRNO_NULL_INPUT);

    EXPECT_EQ(SCF_AddPolicyRule(ctx_, unterminatedNodeId, "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "*", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", unterminatedNodeId, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", 0, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId),
        SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", 8, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId),
        SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, 0, SCF_POLICY_EFFECT_ALLOW, &ruleId),
        SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, 4, SCF_POLICY_EFFECT_ALLOW, &ruleId),
        SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        static_cast<SCF_POLICY_EFFECT>(2), &ruleId), SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(ruleId, 123U);
}

TEST_F(TestRbac, EnableRbacRejectsNullContext)
{
    EXPECT_EQ(SCF_EnableRbac(nullptr, true), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    EXPECT_EQ(SCF_EnableRbac(ctx_, false), SCF_SUCCESS);
}
}