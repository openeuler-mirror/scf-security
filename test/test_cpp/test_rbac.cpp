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
#include <unistd.h>

#include <cstring>

#include "scf.h"
#include "scf_errno.h"

using namespace scf;

namespace scf {
void FreezeNodeRoleMapping(SCF_PolicyCtx *ctx);
}

namespace test {
constexpr size_t NODE_ID_BUFFER_SIZE = 128;
constexpr uint32_t NODE_ROLE_MAP_CAPACITY = 4096;

class TestRbac : public ::testing::Test {
protected:
    void SetUp() override
    {
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
    }

    void *LoadRbacCert(const char *certName)
    {
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

TEST_F(TestRbac, NodeRoleMappingRejectsInvalidInput)
{
    char unterminatedNodeId[NODE_ID_BUFFER_SIZE];
    char nodeId[2] = {0};
    size_t nodeIdLen = 0;
    char cert = 0;
    std::memset(unterminatedNodeId, 'a', sizeof(unterminatedNodeId));
    EXPECT_EQ(SCF_SetNodeRoleMapping(nullptr, "node-1", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, nullptr, SCF_RBAC_ROLE_MASTER), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_UNKNOWN), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(nullptr, "node-1"), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, unterminatedNodeId), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(nullptr, nullptr, 0, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertNodeId(&cert, nullptr, sizeof(nodeId), &nodeIdLen), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertNodeId(&cert, nodeId, sizeof(nodeId), nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetCertRbacRole(nullptr, nullptr), SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestRbac, NodeRoleMappingRejectsEntriesBeyondCapacity)
{
    for (uint32_t i = 0; i < NODE_ROLE_MAP_CAPACITY; ++i) {
        std::string nodeId = "node-" + std::to_string(i);
        ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, nodeId.c_str(), SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    }
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-overflow", SCF_RBAC_ROLE_MASTER), SCF_ERRNO_RBAC_MAP_FULL);
}

TEST_F(TestRbac, NodeRoleMappingIsFrozenAfterConnectionEstablished)
{
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    scf::FreezeNodeRoleMapping(ctx_);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-1", SCF_RBAC_ROLE_SLAVE), SCF_ERRNO_RBAC_MAP_FROZEN);
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-2", SCF_RBAC_ROLE_SLAVE), SCF_ERRNO_RBAC_MAP_FROZEN);
    EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, "node-1"), SCF_ERRNO_RBAC_MAP_FROZEN);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, &src), SCF_SUCCESS);
    EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
}

TEST_F(TestRbac, RbacSr01ErrorsHaveMessages)
{
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_ROLE_UNKNOWN), "RBAC node role is unknown");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_MAP_FULL), "RBAC node role mapping is full");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_MAP_NOT_FOUND), "RBAC node role mapping is not found");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_CERT_NODE_ID_ABSENT), "RBAC certificate node ID extension is absent");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_CERT_ROLE_EXT_ABSENT), "RBAC certificate role extension is absent");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_MAP_FROZEN), "RBAC node role mapping is frozen");
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

TEST_F(TestRbac, CertificateWithoutRbacExtensionsReturnsAbsentAndUnknown)
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
}

TEST_F(TestRbac, NodeRoleLookupRejectsNullOutput)
{
    SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE src = SCF_RBAC_ROLE_SRC_NONE;
    EXPECT_EQ(SCF_GetNodeRbacRole(nullptr, nullptr, "node-1", &role, &src), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", nullptr, &src), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, "node-1", &role, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, nullptr, &role, &src), SCF_ERRNO_RBAC_ROLE_UNKNOWN);
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
    EXPECT_EQ(SCF_GetCertNodeId(cert, smallBuffer, sizeof(smallBuffer), &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);
    EXPECT_EQ(SCF_GetCertNodeId(cert, smallBuffer, 1, &nodeIdLen), SCF_SSL_ERR_PARSE_CERT);
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
}
