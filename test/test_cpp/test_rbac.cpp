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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <thread>
#include <limits>
#include <mutex>
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

class ConnectionAdaptorStub final : public OpenSSLAdaptor {
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

class CertificateIdentityAdaptorStub final : public OpenSSLAdaptor {
public:
    explicit CertificateIdentityAdaptorStub(const std::string &nodeId) : nodeId_(nodeId) {}

    int32_t GetCertExtensionByOid(const void *cert, const char *oid, std::string &value) override
    {
        if (cert == nullptr || oid == nullptr) {
            return SCF_ERRNO_NULL_INPUT;
        }
        if (std::strcmp(oid, SCF_OID_NODE_ID) == 0) {
            value = nodeId_;
            return SCF_SUCCESS;
        }
        if (std::strcmp(oid, SCF_OID_RBAC_ROLE) == 0) {
            value.clear();
            return SCF_SSL_ERR_CERT_EXT_ABSENT;
        }
        value.clear();
        return SCF_SSL_ERR_CERT_EXT_ABSENT;
    }

private:
    std::string nodeId_;
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

struct PermissionConcurrencyState {
    std::atomic_bool hasUnexpectedResult{false};
    std::atomic_bool observedAllow{false};
    std::atomic_bool observedDeny{false};
    std::atomic_bool start{false};
    std::atomic_bool stop{false};
    std::atomic_uint32_t readyCount{0};
    std::mutex waitMutex;
    std::condition_variable waitCondition;
};

static void WaitForStart(PermissionConcurrencyState &state)
{
    std::unique_lock<std::mutex> lock(state.waitMutex);
    ++state.readyCount;
    state.waitCondition.notify_all();
    state.waitCondition.wait(lock, [&state]() { return state.start.load(); });
}

static bool WaitForResult(PermissionConcurrencyState &state, const std::atomic_bool &observed)
{
    std::unique_lock<std::mutex> lock(state.waitMutex);
    bool completed = state.waitCondition.wait_for(
        lock, std::chrono::seconds(5), [&state, &observed]() { return observed.load() || state.stop.load(); });
    return completed && observed.load();
}

static void StartPermissionWorkers(PermissionConcurrencyState &state)
{
    std::unique_lock<std::mutex> lock(state.waitMutex);
    state.waitCondition.wait(lock, [&state]() { return state.readyCount.load() == 2; });
    state.start.store(true);
    lock.unlock();
    state.waitCondition.notify_all();
}

static void CheckPermissions(SCF_PolicyCtx *ctx, const void *cert, PermissionConcurrencyState &state)
{
    WaitForStart(state);
    while (!state.stop.load()) {
        int32_t ret = SCF_CheckResourcePermission(ctx, cert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
        if (ret == SCF_SUCCESS) {
            state.observedAllow.store(true);
        } else if (ret == SCF_ERRNO_RBAC_DENIED) {
            state.observedDeny.store(true);
        } else {
            state.hasUnexpectedResult.store(true);
            state.stop.store(true);
        }
        state.waitCondition.notify_all();
    }
}

static void UpdatePermissionRules(SCF_PolicyCtx *ctx, PermissionConcurrencyState &state)
{
    WaitForStart(state);
    for (uint32_t i = 0; i < 100 && !state.stop.load(); ++i) {
        state.observedAllow.store(false);
        uint32_t ruleId = 0;
        int32_t ret = SCF_AddPolicyRule(ctx, "node-slave-cert", "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
            SCF_POLICY_EFFECT_ALLOW, &ruleId);
        if (ret != SCF_SUCCESS || !WaitForResult(state, state.observedAllow)) {
            state.hasUnexpectedResult.store(true);
            break;
        }
        state.observedDeny.store(false);
        ret = SCF_RemovePolicyRule(ctx, ruleId);
        if (ret != SCF_SUCCESS || !WaitForResult(state, state.observedDeny)) {
            state.hasUnexpectedResult.store(true);
            break;
        }
    }
    state.stop.store(true);
    state.waitCondition.notify_all();
}

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
        int32_t ret = SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, path, certPath.size(), SCF_STORE_FORMAT_PEM);
        EXPECT_EQ(ret, SCF_SUCCESS);
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

struct PolicyRuleBoundaryParam {
    uint32_t resourceTypeBitmap;
    uint32_t actionBitmap;
    SCF_POLICY_EFFECT effect;
    bool wildcardTarget;
};

class TestRbacPolicyRuleBoundary : public TestRbac,
                                   public ::testing::WithParamInterface<PolicyRuleBoundaryParam> {};

struct PermissionBoundaryParam {
    uint32_t resourceType;
    SCF_RESOURCE_ACTION action;
    std::string targetNodeId;
    int32_t expected;
};

class TestRbacPermissionBoundary : public TestRbac,
                                   public ::testing::WithParamInterface<PermissionBoundaryParam> {};

struct NodeIdApiBoundaryParam {
    std::string nodeId;
    bool validForMapping;
    bool validAsPolicySubject;
    bool validAsPolicyTarget;
};

class TestRbacNodeIdApiBoundary : public TestRbac,
                                 public ::testing::WithParamInterface<NodeIdApiBoundaryParam> {};

struct PolicyCacheCaseParam {
    std::string subjectNodeId;
    std::string targetNodeId;
    uint32_t resourceTypeBitmap;
    uint32_t actionBitmap;
    SCF_POLICY_EFFECT effect;
    int32_t expected;
};

class TestRbacPolicyCacheCases : public TestRbac,
                                 public ::testing::WithParamInterface<PolicyCacheCaseParam> {};

struct SubjectIdentityChainParam {
    std::string nodeId;
    SCF_RBAC_ROLE role;
};

class TestRbacSubjectIdentityChain : public TestRbac,
                                     public ::testing::WithParamInterface<SubjectIdentityChainParam> {};

struct SubjectPermissionCombinationParam {
    std::string subjectNodeId;
    SCF_RBAC_ROLE role;
    std::string targetNodeId;
    uint32_t resourceType;
    SCF_RESOURCE_ACTION action;
    SCF_POLICY_EFFECT effect;
};

class TestRbacSubjectPermissionCombinations : public TestRbac,
                                              public ::testing::WithParamInterface<SubjectPermissionCombinationParam> {};

static std::vector<PolicyRuleBoundaryParam> MakePolicyRuleBoundaryParams()
{
    std::vector<PolicyRuleBoundaryParam> params;
    constexpr uint32_t resourceMasks[] = {
        SCF_RES_TYPE_FD,
        SCF_RES_TYPE_NUMA,
        SCF_RES_TYPE_ADDR,
        SCF_RES_TYPE_FD | SCF_RES_TYPE_NUMA,
        SCF_RES_TYPE_FD | SCF_RES_TYPE_ADDR,
        SCF_RES_TYPE_NUMA | SCF_RES_TYPE_ADDR,
        SCF_RES_TYPE_ALL,
    };
    constexpr uint32_t actionMasks[] = {
        SCF_RES_ACTION_APPLY,
        SCF_RES_ACTION_RELEASE,
        SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE,
    };
    constexpr SCF_POLICY_EFFECT effects[] = {SCF_POLICY_EFFECT_ALLOW, SCF_POLICY_EFFECT_DENY};
    for (uint32_t resourceMask : resourceMasks) {
        for (uint32_t actionMask : actionMasks) {
            for (SCF_POLICY_EFFECT effect : effects) {
                params.push_back({resourceMask, actionMask, effect, false});
                params.push_back({resourceMask, actionMask, effect, true});
            }
        }
    }
    return params;
}

static std::vector<PermissionBoundaryParam> MakePermissionBoundaryParams()
{
    std::vector<PermissionBoundaryParam> params;
    constexpr uint32_t validResourceTypes[] = {SCF_RES_TYPE_FD, SCF_RES_TYPE_NUMA, SCF_RES_TYPE_ADDR};
    constexpr SCF_RESOURCE_ACTION validActions[] = {SCF_RES_ACTION_APPLY, SCF_RES_ACTION_RELEASE};
    for (uint32_t resourceType : validResourceTypes) {
        for (SCF_RESOURCE_ACTION action : validActions) {
            params.push_back({resourceType, action, "a", SCF_SUCCESS});
            params.push_back({resourceType, action, "*", SCF_ERRNO_INVALID_PARAM});
            params.push_back({resourceType, action, std::string(MAX_NODE_ID_LEN - 1, 'x'), SCF_SUCCESS});
        }
    }
    constexpr uint32_t invalidResourceTypes[] = {0, 3, 5, 6, 7, 8, std::numeric_limits<uint32_t>::max()};
    for (uint32_t resourceType : invalidResourceTypes) {
        params.push_back({resourceType, SCF_RES_ACTION_APPLY, "target", SCF_ERRNO_INVALID_PARAM});
    }
    constexpr SCF_RESOURCE_ACTION invalidActions[] = {
        SCF_RES_ACTION_UNKNOWN,
        static_cast<SCF_RESOURCE_ACTION>(SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE),
        static_cast<SCF_RESOURCE_ACTION>(4),
        static_cast<SCF_RESOURCE_ACTION>(std::numeric_limits<uint32_t>::max()),
    };
    for (SCF_RESOURCE_ACTION action : invalidActions) {
        params.push_back({SCF_RES_TYPE_FD, action, "target", SCF_ERRNO_INVALID_PARAM});
    }
    params.push_back({SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, "", SCF_ERRNO_INVALID_PARAM});
    params.push_back(
        {SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, std::string(MAX_NODE_ID_LEN, 'x'), SCF_ERRNO_INVALID_PARAM});
    return params;
}

static std::vector<PolicyCacheCaseParam> MakeOneThousandPolicyCacheParams()
{
    std::vector<PolicyCacheCaseParam> params;
    params.reserve(1000);
    constexpr uint32_t resourceMasks[] = {
        SCF_RES_TYPE_FD,
        SCF_RES_TYPE_NUMA,
        SCF_RES_TYPE_ADDR,
        SCF_RES_TYPE_ALL,
    };
    constexpr uint32_t actionMasks[] = {
        SCF_RES_ACTION_APPLY,
        SCF_RES_ACTION_RELEASE,
        SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE,
    };
    for (uint32_t i = 0; i < 1000; ++i) {
        size_t subjectLength = static_cast<size_t>(i % (MAX_NODE_ID_LEN - 1)) + 1;
        size_t targetLength = static_cast<size_t>((i * 7) % (MAX_NODE_ID_LEN - 1)) + 1;
        bool valid = true;
        switch (i % 25) {
            case 0:
                subjectLength = 0;
                valid = false;
                break;
            case 1:
                subjectLength = MAX_NODE_ID_LEN - 1;
                break;
            case 2:
                subjectLength = (MAX_NODE_ID_LEN - 1) + 1;
                valid = false;
                break;
            case 3:
                subjectLength = MAX_NODE_ID_LEN + 1;
                valid = false;
                break;
            case 4:
                targetLength = 0;
                valid = false;
                break;
            case 5:
                targetLength = MAX_NODE_ID_LEN - 1;
                break;
            case 6:
                targetLength = (MAX_NODE_ID_LEN - 1) + 1;
                valid = false;
                break;
            case 7:
                targetLength = MAX_NODE_ID_LEN + 1;
                valid = false;
                break;
            default:
                break;
        }
        params.push_back({
            std::string(subjectLength, static_cast<char>('a' + (i % 26))),
            i % 10 == 0 && valid ? "*" : std::string(targetLength, static_cast<char>('A' + (i % 26))),
            resourceMasks[i % 4],
            actionMasks[i % 3],
            i % 2 == 0 ? SCF_POLICY_EFFECT_ALLOW : SCF_POLICY_EFFECT_DENY,
            valid ? SCF_SUCCESS : static_cast<int32_t>(SCF_ERRNO_RBAC_POLICY_INVALID),
        });
    }
    return params;
}

static std::vector<SubjectPermissionCombinationParam> MakeSubjectPermissionCombinationParams()
{
    std::vector<SubjectPermissionCombinationParam> params;
    const std::string subjects[] = {"a", "*"};
    constexpr SCF_RBAC_ROLE roles[] = {SCF_RBAC_ROLE_MASTER, SCF_RBAC_ROLE_SLAVE};
    const std::string targets[] = {
        "a", "*", std::string(MAX_NODE_ID_LEN - 1, 't'), "", std::string(MAX_NODE_ID_LEN, 'u'),
        std::string(MAX_NODE_ID_LEN + 1, 'v')};
    constexpr uint32_t resourceTypes[] = {
        SCF_RES_TYPE_FD, SCF_RES_TYPE_NUMA, SCF_RES_TYPE_ADDR, SCF_RES_TYPE_FD | SCF_RES_TYPE_NUMA,
        SCF_RES_TYPE_ALL, SCF_RES_TYPE_NONE, 8};
    constexpr SCF_RESOURCE_ACTION actions[] = {
        SCF_RES_ACTION_APPLY, SCF_RES_ACTION_RELEASE,
        static_cast<SCF_RESOURCE_ACTION>(SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE), SCF_RES_ACTION_UNKNOWN,
        static_cast<SCF_RESOURCE_ACTION>(4),
        static_cast<SCF_RESOURCE_ACTION>(std::numeric_limits<uint32_t>::max())};
    constexpr SCF_POLICY_EFFECT effects[] = {
        SCF_POLICY_EFFECT_ALLOW, SCF_POLICY_EFFECT_DENY, static_cast<SCF_POLICY_EFFECT>(2),
        static_cast<SCF_POLICY_EFFECT>(std::numeric_limits<uint32_t>::max())};
    params.reserve(4032);
    for (const auto &subject : subjects) {
        for (SCF_RBAC_ROLE role : roles) {
            for (const auto &target : targets) {
                for (uint32_t resourceType : resourceTypes) {
                    for (SCF_RESOURCE_ACTION action : actions) {
                        for (SCF_POLICY_EFFECT effect : effects) {
                            params.push_back({subject, role, target, resourceType, action, effect});
                        }
                    }
                }
            }
        }
    }
    return params;
}

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
    int32_t ret = SCF_GetCertNodeId(overLimitCert, nodeIdBuffer, MAX_NODE_ID_LEN, &nodeIdLen);
    EXPECT_EQ(ret, SCF_SSL_ERR_PARSE_CERT);
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

TEST_F(TestRbac, RbacSr03ErrorsHaveMessages)
{
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_DISABLED), "RBAC is disabled");
    EXPECT_STREQ(GetErrorMessage(SCF_ERRNO_RBAC_DENIED), "RBAC access is denied");
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
    int32_t ret = SCF_CheckResourcePermission(ctx_, &cert, "node-1", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_NOT_INIT);
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
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &firstRuleId);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_NE(firstRuleId, 0U);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", "*", SCF_RES_TYPE_ALL, SCF_RES_ACTION_RELEASE, SCF_POLICY_EFFECT_DENY, &secondRuleId);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_NE(secondRuleId, firstRuleId);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &actualCount);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_DUPLICATE);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 1, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 1U);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 2, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, firstRuleId), SCF_SUCCESS);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, firstRuleId), SCF_ERRNO_RBAC_POLICY_NOT_FOUND);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, 0), SCF_ERRNO_INVALID_PARAM);
    uint32_t removedRuleId = firstRuleId;
    uint32_t readdedRuleId = 0;
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &readdedRuleId);
    EXPECT_EQ(ret, SCF_SUCCESS);
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
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_DENY, &conflictingRuleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_DUPLICATE);
    EXPECT_EQ(conflictingRuleId, 0U);
}

TEST_F(TestRbac, PolicyRuleCapacityRejectsEntryBeyondLimit)
{
    uint32_t ruleId = 0;
    for (uint32_t i = 0; i < MAX_POLICY_RULE_SIZE; ++i) {
        const std::string subjectNodeId = "subject-" + std::to_string(i);
        int32_t ret = SCF_AddPolicyRule(ctx_, subjectNodeId.c_str(), "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
            SCF_POLICY_EFFECT_ALLOW, &ruleId);
        ASSERT_EQ(ret, SCF_SUCCESS);
    }
    EXPECT_EQ(ruleId, MAX_POLICY_RULE_SIZE);

    ruleId = 123;
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "overflow", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_FULL);
    EXPECT_EQ(ruleId, 123U);
}

TEST_F(TestRbac, PolicyRuleIdCollisionReturnsIdSpaceError)
{
    uint32_t firstRuleId = 0;
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "node-1", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &firstRuleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ctx_->nextPolicyRuleId = firstRuleId;

    uint32_t conflictingRuleId = 123;
    ret = SCF_AddPolicyRule(
        ctx_, "node-2", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &conflictingRuleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_FULL);
    EXPECT_EQ(conflictingRuleId, 123U);
}

TEST_F(TestRbac, PolicyRuleIdExhaustionIsPermanent)
{
    ctx_->nextPolicyRuleId = std::numeric_limits<uint32_t>::max() - 1;
    uint32_t penultimateRuleId = 0;
    uint32_t lastRuleId = 0;
    int32_t ret = SCF_AddPolicyRule(ctx_, "penultimate", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &penultimateRuleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(penultimateRuleId, std::numeric_limits<uint32_t>::max() - 1);
    ret = SCF_AddPolicyRule(
        ctx_, "last", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &lastRuleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(lastRuleId, std::numeric_limits<uint32_t>::max());
    EXPECT_EQ(ctx_->nextPolicyRuleId, 0U);

    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, lastRuleId), SCF_SUCCESS);
    uint32_t exhaustedRuleId = 123;
    ret = SCF_AddPolicyRule(ctx_, "after-exhaustion", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &exhaustedRuleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_FULL);
    EXPECT_EQ(exhaustedRuleId, 123U);
}

TEST_F(TestRbac, AddPolicyRuleRejectsEachInvalidField)
{
    char unterminatedNodeId[NODE_ID_BUFFER_SIZE];
    ASSERT_EQ(memset_s(unterminatedNodeId, sizeof(unterminatedNodeId), 'a', sizeof(unterminatedNodeId)), EOK);
    uint32_t ruleId = 123;

    int32_t ret = SCF_AddPolicyRule(
        nullptr, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(ruleId, 123U);
    ret = SCF_AddPolicyRule(
        ctx_, nullptr, "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(ruleId, 123U);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", nullptr, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(ruleId, 123U);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    ret = SCF_AddPolicyRule(
        ctx_, unterminatedNodeId, "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret =
        SCF_AddPolicyRule(ctx_, "*", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", unterminatedNodeId, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret = SCF_AddPolicyRule(ctx_, "node-1", "node-2", 0, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret = SCF_AddPolicyRule(ctx_, "node-1", "node-2", 8, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret = SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, 0, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret = SCF_AddPolicyRule(ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, 4, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    ret = SCF_AddPolicyRule(
        ctx_, "node-1", "node-2", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, static_cast<SCF_POLICY_EFFECT>(2), &ruleId);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_POLICY_INVALID);
    EXPECT_EQ(ruleId, 123U);
}

TEST_F(TestRbac, EnableRbacRejectsNullContext)
{
    EXPECT_EQ(SCF_EnableRbac(nullptr, true), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    EXPECT_EQ(SCF_EnableRbac(ctx_, false), SCF_SUCCESS);
}

TEST_F(TestRbac, ResourcePermissionRequiresEnabledRbacAndNonNullInput)
{
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);

    int32_t ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DISABLED);
    ret = SCF_EnableRbac(ctx_, true);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(nullptr, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_CheckResourcePermission(ctx_, nullptr, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_CheckResourcePermission(ctx_, cert, nullptr, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
    ret = SCF_EnableRbac(ctx_, false);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DISABLED);
}

TEST_F(TestRbac, ResourcePermissionValidatesTargetNodeId)
{
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    const std::string maxTargetNodeId(MAX_NODE_ID_LEN - 1, 'a');
    const std::string overlongTargetNodeId(MAX_NODE_ID_LEN, 'b');
    char unterminatedTargetNodeId[MAX_NODE_ID_LEN];
    int32_t ret =
        memset_s(unterminatedTargetNodeId, sizeof(unterminatedTargetNodeId), 'c', sizeof(unterminatedTargetNodeId));
    ASSERT_EQ(ret, EOK);

    ret = SCF_CheckResourcePermission(ctx_, cert, "", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(ctx_, cert, "a", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, cert, maxTargetNodeId.c_str(), SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, cert, overlongTargetNodeId.c_str(), SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(ctx_, cert, unterminatedTargetNodeId, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestRbac, ResourcePermissionValidatesResourceTypeAndAction)
{
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);

    int32_t ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_NONE, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_ALL, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(
        ctx_, cert, "node-target", SCF_RES_TYPE_FD | SCF_RES_TYPE_NUMA, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", 8, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_UNKNOWN);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    SCF_RESOURCE_ACTION combinedAction =
        static_cast<SCF_RESOURCE_ACTION>(SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE);
    ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, combinedAction);
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
    ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, static_cast<SCF_RESOURCE_ACTION>(4));
    EXPECT_EQ(ret, SCF_ERRNO_INVALID_PARAM);
}

TEST_F(TestRbac, ResourcePermissionAppliesDefaultRules)
{
    void *masterCert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(masterCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, masterCert, "any-node", SCF_RES_TYPE_ADDR, SCF_RES_ACTION_RELEASE);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestRbac, ResourcePermissionAppliesSlaveAndUnknownDefaults)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret =
        SCF_CheckResourcePermission(ctx_, slaveCert, "node-slave-cert", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "other-node", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);
}

TEST_F(TestRbac, ResourcePermissionUsesMappedRoleWhenCertificateRoleIsAbsent)
{
    void *nodeOnlyCert = LoadRbacCert("rbac_node_only_cert.pem");
    ASSERT_NE(nodeOnlyCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-mapped", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, nodeOnlyCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "node-mapped", SCF_RBAC_ROLE_SLAVE), SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, nodeOnlyCert, "node-mapped", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, nodeOnlyCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);
}

TEST_F(TestRbac, ResourcePermissionIgnoresRulesWithMismatchedFields)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    uint32_t ruleId = 0;
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "other-subject", "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "different-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "other-node", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);
}

TEST_F(TestRbac, ResourcePermissionPrioritizesCustomRules)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    uint32_t ruleId = 0;
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "node-slave-cert", "*", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_DENY, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(
        ctx_, "node-slave-cert", "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "resource-target", SCF_RES_TYPE_ALL,
        SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE, SCF_POLICY_EFFECT_DENY, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "resource-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "resource-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestRbac, ResourcePermissionPrioritizesDenyForEquallySpecificRules)
{
    void *masterCert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(masterCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    uint32_t ruleId = 0;
    int32_t ret = SCF_AddPolicyRule(
        ctx_, "node-cert", "other-node", SCF_RES_TYPE_ALL, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(
        ctx_, "node-cert", "*", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_DENY, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, masterCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);

    ret = SCF_AddPolicyRule(ctx_, "node-cert", "deny-first-node", SCF_RES_TYPE_ALL, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_DENY, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(
        ctx_, "node-cert", "*", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_RELEASE, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, masterCert, "deny-first-node", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_RELEASE);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);
}

TEST_F(TestRbac, ResourcePermissionSupportsAllResourceTypesAndReleaseRules)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    uint32_t ruleId = 0;
    int32_t ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "numa-target", SCF_RES_TYPE_NUMA,
        SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE, SCF_POLICY_EFFECT_DENY, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "numa-target", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "numa-target", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_RELEASE);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "addr-target", SCF_RES_TYPE_ALL, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_DENY, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_AddPolicyRule(ctx_, "node-slave-cert", "addr-target", SCF_RES_TYPE_ADDR, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "addr-target", SCF_RES_TYPE_ADDR, SCF_RES_ACTION_RELEASE);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestRbac, ResourcePermissionReflectsPolicyRuleLifecycle)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, slaveCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);
    uint32_t ruleId = 0;
    ret = SCF_AddPolicyRule(
        ctx_, "node-slave-cert", "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId);
    ASSERT_EQ(ret, SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SUCCESS);
    ASSERT_EQ(SCF_RemovePolicyRule(ctx_, ruleId), SCF_SUCCESS);
    ret = SCF_CheckResourcePermission(ctx_, slaveCert, "other-node", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_DENIED);
}

TEST_F(TestRbac, ResourcePermissionReturnsUnknownRole)
{
    void *nodeOnlyCert = LoadRbacCert("rbac_node_only_cert.pem");
    ASSERT_NE(nodeOnlyCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, nodeOnlyCert, "node-mapped", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_RBAC_ROLE_UNKNOWN);
}

TEST_F(TestRbac, ResourcePermissionRejectsCertificateWithoutNodeId)
{
    void *cert = LoadRbacCert("test_cert/client.pem");
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_ERRNO_CERT_NODE_ID_ABSENT);
}

TEST_F(TestRbac, ResourcePermissionPreservesMalformedNodeIdError)
{
    void *cert = LoadRbacCert("rbac_invalid_utf8_cert.pem");
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, ResourcePermissionPreservesMalformedRoleError)
{
    void *cert = LoadRbacCert("rbac_unknown_role_cert.pem");
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    int32_t ret = SCF_CheckResourcePermission(ctx_, cert, "node-target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY);
    EXPECT_EQ(ret, SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestRbac, ResourcePermissionSupportsConcurrentRuleUpdates)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    PermissionConcurrencyState state;
    std::thread checker(CheckPermissions, ctx_, slaveCert, std::ref(state));
    std::thread updater(UpdatePermissionRules, ctx_, std::ref(state));
    StartPermissionWorkers(state);
    checker.join();
    updater.join();
    EXPECT_FALSE(state.hasUnexpectedResult.load());
    EXPECT_TRUE(state.observedAllow.load());
    EXPECT_TRUE(state.observedDeny.load());
}

TEST_P(TestRbacPolicyRuleBoundary, AcceptsEveryDocumentedBitmapEffectAndTargetCombination)
{
    const PolicyRuleBoundaryParam &param = GetParam();
    const char *targetNodeId = param.wildcardTarget ? "*" : "target";
    uint32_t ruleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "subject", targetNodeId, param.resourceTypeBitmap, param.actionBitmap,
        param.effect, &ruleId), SCF_SUCCESS);
    EXPECT_NE(ruleId, 0U);

    SCF_PolicyRule cachedRule[1];
    uint32_t actualCount = 0;
    ASSERT_EQ(SCF_ListPolicyRules(ctx_, cachedRule, 1, &actualCount), SCF_SUCCESS);
    ASSERT_EQ(actualCount, 1U);
    EXPECT_EQ(cachedRule[0].subjectNodeId, "subject");
    EXPECT_EQ(cachedRule[0].targetNodeId, targetNodeId);
    EXPECT_EQ(cachedRule[0].resourceTypeBitmap, param.resourceTypeBitmap);
    EXPECT_EQ(cachedRule[0].actionBitmap, param.actionBitmap);
    EXPECT_EQ(cachedRule[0].effect, param.effect);
}

INSTANTIATE_TEST_SUITE_P(AllPolicyRuleBoundaries, TestRbacPolicyRuleBoundary,
    ::testing::ValuesIn(MakePolicyRuleBoundaryParams()));

TEST_P(TestRbacPermissionBoundary, ValidatesOnlyPublicInputContractBeforeDecision)
{
    void *masterCert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(masterCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    const PermissionBoundaryParam &param = GetParam();
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, masterCert, param.targetNodeId.c_str(), param.resourceType,
        param.action), param.expected);
}

INSTANTIATE_TEST_SUITE_P(AllPermissionBoundaries, TestRbacPermissionBoundary,
    ::testing::ValuesIn(MakePermissionBoundaryParams()));

TEST_P(TestRbacNodeIdApiBoundary, AppliesWildcardAndLengthRulesConsistentlyAcrossPublicApis)
{
    const NodeIdApiBoundaryParam &param = GetParam();
    const char *nodeId = param.nodeId.c_str();
    const int32_t mappingExpected = param.validForMapping ? SCF_SUCCESS : SCF_ERRNO_INVALID_PARAM;
    EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, nodeId, SCF_RBAC_ROLE_MASTER), mappingExpected);
    if (param.validForMapping) {
        SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
        SCF_RBAC_ROLE_SOURCE source = SCF_RBAC_ROLE_SRC_NONE;
        EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, nodeId, &role, &source), SCF_SUCCESS);
        EXPECT_EQ(role, SCF_RBAC_ROLE_MASTER);
        EXPECT_EQ(source, SCF_RBAC_ROLE_SRC_MAPPING);
        bool isMaster = false;
        EXPECT_EQ(SCF_IsMasterNode(ctx_, nodeId, &isMaster), SCF_SUCCESS);
        EXPECT_TRUE(isMaster);
    } else {
        SCF_RBAC_ROLE role = SCF_RBAC_ROLE_UNKNOWN;
        SCF_RBAC_ROLE_SOURCE source = SCF_RBAC_ROLE_SRC_NONE;
        bool isMaster = false;
        EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, nullptr, nodeId, &role, &source), SCF_ERRNO_INVALID_PARAM);
        EXPECT_EQ(SCF_IsMasterNode(ctx_, nodeId, &isMaster), SCF_ERRNO_INVALID_PARAM);
        EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nodeId), SCF_ERRNO_INVALID_PARAM);
    }

    uint32_t subjectRuleId = 0;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, nodeId, "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &subjectRuleId),
        param.validAsPolicySubject ? SCF_SUCCESS : SCF_ERRNO_RBAC_POLICY_INVALID);

    uint32_t targetRuleId = 0;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, "subject", nodeId, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &targetRuleId),
        param.validAsPolicyTarget ? SCF_SUCCESS : SCF_ERRNO_RBAC_POLICY_INVALID);

    void *masterCert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(masterCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, masterCert, nodeId, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY),
        param.validForMapping ? SCF_SUCCESS : SCF_ERRNO_INVALID_PARAM);

    if (param.validForMapping) {
        EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nodeId), SCF_SUCCESS);
        EXPECT_EQ(SCF_RemoveNodeRoleMapping(ctx_, nodeId), SCF_ERRNO_RBAC_MAP_NOT_FOUND);
    }
}

INSTANTIATE_TEST_SUITE_P(ExternalHeaderNodeIds, TestRbacNodeIdApiBoundary,
    ::testing::Values(
        NodeIdApiBoundaryParam{"", false, false, false},
        NodeIdApiBoundaryParam{"*", false, false, true},
        NodeIdApiBoundaryParam{"a", true, true, true},
        NodeIdApiBoundaryParam{std::string(MAX_NODE_ID_LEN - 1, 'm'), true, true, true},
        NodeIdApiBoundaryParam{std::string(MAX_NODE_ID_LEN, 'n'), false, false, false},
        NodeIdApiBoundaryParam{std::string(MAX_NODE_ID_LEN + 1, 'o'), false, false, false}));

TEST_F(TestRbac, CertificateNodeIdOutputBufferCoversZeroExactMaxAndMaxPlusOne)
{
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    char nodeIdBuffer[MAX_NODE_ID_LEN + 1] = {0};
    size_t nodeIdLen = 0;

    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, 0, &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, 1, &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, 9, &nodeIdLen), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, 10, &nodeIdLen), SCF_SUCCESS);
    EXPECT_EQ(nodeIdLen, 9U);
    EXPECT_STREQ(nodeIdBuffer, "node-cert");
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, MAX_NODE_ID_LEN - 1, &nodeIdLen), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, MAX_NODE_ID_LEN, &nodeIdLen), SCF_SUCCESS);
    EXPECT_EQ(SCF_GetCertNodeId(cert, nodeIdBuffer, MAX_NODE_ID_LEN + 1, &nodeIdLen), SCF_SUCCESS);
}

TEST_F(TestRbac, ListApisCoverNullZeroOneExactAndOversizedCapacity)
{
    char masterNodes[2][MAX_NODE_ID_LEN] = {{0}};
    SCF_PolicyRule rules[2];
    uint32_t actualCount = 0;
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "master-a", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, "master-b", SCF_RBAC_ROLE_MASTER), SCF_SUCCESS);
    uint32_t ruleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "subject-a", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "subject-b", "target", SCF_RES_TYPE_NUMA, SCF_RES_ACTION_RELEASE,
        SCF_POLICY_EFFECT_DENY, &ruleId), SCF_SUCCESS);

    EXPECT_EQ(SCF_ListMasterNodes(nullptr, masterNodes, 2, &actualCount), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, nullptr, 2, &actualCount), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 2, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 0, &actualCount), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 1, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 1U);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, 2, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);
    EXPECT_EQ(SCF_ListMasterNodes(ctx_, masterNodes, std::numeric_limits<uint32_t>::max(), &actualCount),
        SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);

    EXPECT_EQ(SCF_ListPolicyRules(nullptr, rules, 2, &actualCount), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, nullptr, 2, &actualCount), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 2, nullptr), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 0, &actualCount), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 1, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 1U);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, 2, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, rules, std::numeric_limits<uint32_t>::max(), &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 2U);
}

TEST_F(TestRbac, RuleIdApisCoverZeroOneMaxAndMaxPlusOneWrap)
{
    uint32_t ruleId = 0;
    EXPECT_EQ(SCF_RemovePolicyRule(nullptr, 1), SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, 0), SCF_ERRNO_INVALID_PARAM);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, 1), SCF_ERRNO_RBAC_POLICY_NOT_FOUND);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, std::numeric_limits<uint32_t>::max()), SCF_ERRNO_RBAC_POLICY_NOT_FOUND);

    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "subject", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);
    EXPECT_EQ(ruleId, 1U);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, ruleId), SCF_SUCCESS);

    ctx_->nextPolicyRuleId = std::numeric_limits<uint32_t>::max();
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "subject-max", "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY,
        SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);
    EXPECT_EQ(ruleId, std::numeric_limits<uint32_t>::max());
    EXPECT_EQ(ctx_->nextPolicyRuleId, 0U);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, ruleId), SCF_SUCCESS);
}

TEST_F(TestRbac, ResourcePermissionRejectsEachNullPointerBeforePolicyDecision)
{
    void *cert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    EXPECT_EQ(SCF_CheckResourcePermission(nullptr, cert, "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY),
        SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, nullptr, "target", SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY),
        SCF_ERRNO_NULL_INPUT);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, nullptr, SCF_RES_TYPE_FD, SCF_RES_ACTION_APPLY),
        SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestRbac, CustomDecisionFallsBackOnlyWhenNoRuleMatches)
{
    void *slaveCert = LoadRbacCert("rbac_slave_cert.pem");
    ASSERT_NE(slaveCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    uint32_t ruleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "node-slave-cert", "other-target", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);

    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, slaveCert, "unmatched-target", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY), SCF_ERRNO_RBAC_DENIED);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, slaveCert, "other-target", SCF_RES_TYPE_NUMA,
        SCF_RES_ACTION_APPLY), SCF_ERRNO_RBAC_DENIED);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, slaveCert, "other-target", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_RELEASE), SCF_ERRNO_RBAC_DENIED);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, slaveCert, "other-target", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY), SCF_SUCCESS);
}

TEST_F(TestRbac, CustomDenyDecisionOverridesDefaultMasterAllow)
{
    void *masterCert = LoadRbacCert("rbac_cert.pem");
    ASSERT_NE(masterCert, nullptr);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
    uint32_t ruleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "node-cert", "*", SCF_RES_TYPE_ALL,
        SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE, SCF_POLICY_EFFECT_DENY, &ruleId), SCF_SUCCESS);
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, masterCert, "external-target", SCF_RES_TYPE_ADDR,
        SCF_RES_ACTION_RELEASE), SCF_ERRNO_RBAC_DENIED);
}

TEST_F(TestRbac, PolicyCacheSnapshotIsIndependentFromCallerMutation)
{
    uint32_t ruleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, "subject", "*", SCF_RES_TYPE_ALL,
        SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE, SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_SUCCESS);
    SCF_PolicyRule firstSnapshot[1];
    uint32_t actualCount = 0;
    ASSERT_EQ(SCF_ListPolicyRules(ctx_, firstSnapshot, 1, &actualCount), SCF_SUCCESS);
    ASSERT_EQ(actualCount, 1U);
    firstSnapshot[0].subjectNodeId = "mutated-subject";
    firstSnapshot[0].targetNodeId = "mutated-target";
    firstSnapshot[0].effect = SCF_POLICY_EFFECT_DENY;

    SCF_PolicyRule secondSnapshot[1];
    ASSERT_EQ(SCF_ListPolicyRules(ctx_, secondSnapshot, 1, &actualCount), SCF_SUCCESS);
    ASSERT_EQ(actualCount, 1U);
    EXPECT_EQ(secondSnapshot[0].ruleId, ruleId);
    EXPECT_EQ(secondSnapshot[0].subjectNodeId, "subject");
    EXPECT_EQ(secondSnapshot[0].targetNodeId, "*");
    EXPECT_EQ(secondSnapshot[0].effect, SCF_POLICY_EFFECT_ALLOW);
}

TEST_P(TestRbacSubjectIdentityChain, ComparesAsteriskAndOrdinaryNodeAcrossTheCompletePermissionChain)
{
    const SubjectIdentityChainParam &param = GetParam();
    CertificateIdentityAdaptorStub adaptor(param.nodeId);
    ASSERT_NE(GetLibraryAdaptorSlot(), nullptr);
    ScopedAdaptorOverride adaptorOverride(&adaptor);
    int certificateToken = 0;
    const void *cert = &certificateToken;

    char parsedNodeId[MAX_NODE_ID_LEN] = {0};
    size_t parsedNodeIdLen = 0;
    if (param.nodeId == "*") {
        EXPECT_EQ(SCF_GetCertNodeId(cert, parsedNodeId, sizeof(parsedNodeId), &parsedNodeIdLen),
            SCF_SSL_ERR_PARSE_CERT);
        EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, param.nodeId.c_str(), param.role), SCF_ERRNO_INVALID_PARAM);
        SCF_RBAC_ROLE resolvedRole = SCF_RBAC_ROLE_UNKNOWN;
        SCF_RBAC_ROLE_SOURCE roleSource = SCF_RBAC_ROLE_SRC_NONE;
        EXPECT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &resolvedRole, &roleSource), SCF_SSL_ERR_PARSE_CERT);
        uint32_t ruleId = 0;
        EXPECT_EQ(SCF_AddPolicyRule(ctx_, param.nodeId.c_str(), "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &ruleId), SCF_ERRNO_RBAC_POLICY_INVALID);
        EXPECT_EQ(SCF_AddPolicyRule(ctx_, param.nodeId.c_str(), "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_DENY, &ruleId), SCF_ERRNO_RBAC_POLICY_INVALID);
        ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
        EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY), SCF_SSL_ERR_PARSE_CERT);
        return;
    }
    ASSERT_EQ(SCF_GetCertNodeId(cert, parsedNodeId, sizeof(parsedNodeId), &parsedNodeIdLen), SCF_SUCCESS);
    EXPECT_EQ(std::string(parsedNodeId, parsedNodeIdLen), param.nodeId);
    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, param.nodeId.c_str(), param.role), SCF_SUCCESS);

    SCF_RBAC_ROLE resolvedRole = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE roleSource = SCF_RBAC_ROLE_SRC_NONE;
    ASSERT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &resolvedRole, &roleSource), SCF_SUCCESS);
    EXPECT_EQ(resolvedRole, param.role);
    EXPECT_EQ(roleSource, SCF_RBAC_ROLE_SRC_MAPPING);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);

    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, param.nodeId.c_str(), SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY), SCF_SUCCESS);
    const int32_t defaultCrossNodeDecision = param.role == SCF_RBAC_ROLE_MASTER ? SCF_SUCCESS : SCF_ERRNO_RBAC_DENIED;
    EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, "resource-node", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY), defaultCrossNodeDecision);

    uint32_t allowRuleId = 0;
    const int32_t expectedRuleResult = param.nodeId == "*" ? SCF_ERRNO_RBAC_POLICY_INVALID : SCF_SUCCESS;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, param.nodeId.c_str(), "resource-node", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_ALLOW, &allowRuleId), expectedRuleResult);
    if (expectedRuleResult == SCF_SUCCESS) {
        EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY), SCF_SUCCESS);
        ASSERT_EQ(SCF_RemovePolicyRule(ctx_, allowRuleId), SCF_SUCCESS);
    } else {
        EXPECT_EQ(allowRuleId, 0U);
        EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY), defaultCrossNodeDecision);
    }

    uint32_t denyRuleId = 0;
    EXPECT_EQ(SCF_AddPolicyRule(ctx_, param.nodeId.c_str(), "resource-node", SCF_RES_TYPE_FD,
        SCF_RES_ACTION_APPLY, SCF_POLICY_EFFECT_DENY, &denyRuleId), expectedRuleResult);
    if (expectedRuleResult == SCF_SUCCESS) {
        EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY), SCF_ERRNO_RBAC_DENIED);
        EXPECT_EQ(SCF_RemovePolicyRule(ctx_, denyRuleId), SCF_SUCCESS);
    } else {
        EXPECT_EQ(denyRuleId, 0U);
        EXPECT_EQ(SCF_CheckResourcePermission(ctx_, cert, "resource-node", SCF_RES_TYPE_FD,
            SCF_RES_ACTION_APPLY), defaultCrossNodeDecision);
    }
}

INSTANTIATE_TEST_SUITE_P(AsteriskAndOrdinarySubjects, TestRbacSubjectIdentityChain,
    ::testing::Values(
        SubjectIdentityChainParam{"a", SCF_RBAC_ROLE_MASTER},
        SubjectIdentityChainParam{"a", SCF_RBAC_ROLE_SLAVE},
        SubjectIdentityChainParam{"*", SCF_RBAC_ROLE_MASTER},
        SubjectIdentityChainParam{"*", SCF_RBAC_ROLE_SLAVE}));

TEST_P(TestRbacSubjectPermissionCombinations, ComparesRuleValidationAndPermissionDecisionForEveryCombination)
{
    const SubjectPermissionCombinationParam &param = GetParam();
    CertificateIdentityAdaptorStub adaptor(param.subjectNodeId);
    ASSERT_NE(GetLibraryAdaptorSlot(), nullptr);
    ScopedAdaptorOverride adaptorOverride(&adaptor);
    int certificateToken = 0;
    const void *cert = &certificateToken;

    const bool validPolicyTarget = !param.targetNodeId.empty() && param.targetNodeId.size() < MAX_NODE_ID_LEN;
    const bool validPermissionTarget = validPolicyTarget && param.targetNodeId != "*";
    const bool validPermissionResource = param.resourceType == SCF_RES_TYPE_FD ||
        param.resourceType == SCF_RES_TYPE_NUMA || param.resourceType == SCF_RES_TYPE_ADDR;
    const bool validPermissionAction =
        param.action == SCF_RES_ACTION_APPLY || param.action == SCF_RES_ACTION_RELEASE;
    if (param.subjectNodeId == "*") {
        char parsedNodeId[MAX_NODE_ID_LEN] = {0};
        size_t parsedNodeIdLen = 0;
        EXPECT_EQ(SCF_GetCertNodeId(cert, parsedNodeId, sizeof(parsedNodeId), &parsedNodeIdLen),
            SCF_SSL_ERR_PARSE_CERT);
        EXPECT_EQ(SCF_SetNodeRoleMapping(ctx_, param.subjectNodeId.c_str(), param.role), SCF_ERRNO_INVALID_PARAM);
        uint32_t ruleId = 0;
        EXPECT_EQ(SCF_AddPolicyRule(ctx_, param.subjectNodeId.c_str(), param.targetNodeId.c_str(),
            param.resourceType, static_cast<uint32_t>(param.action), param.effect, &ruleId),
            SCF_ERRNO_RBAC_POLICY_INVALID);
        ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);
        const int32_t permissionResult = SCF_CheckResourcePermission(ctx_, cert, param.targetNodeId.c_str(),
            param.resourceType, param.action);
        if (!validPermissionTarget || !validPermissionResource || !validPermissionAction) {
            EXPECT_EQ(permissionResult, SCF_ERRNO_INVALID_PARAM);
        } else {
            EXPECT_EQ(permissionResult, SCF_SSL_ERR_PARSE_CERT);
        }
        return;
    }

    ASSERT_EQ(SCF_SetNodeRoleMapping(ctx_, param.subjectNodeId.c_str(), param.role), SCF_SUCCESS);
    SCF_RBAC_ROLE resolvedRole = SCF_RBAC_ROLE_UNKNOWN;
    SCF_RBAC_ROLE_SOURCE roleSource = SCF_RBAC_ROLE_SRC_NONE;
    ASSERT_EQ(SCF_GetNodeRbacRole(ctx_, cert, nullptr, &resolvedRole, &roleSource), SCF_SUCCESS);
    ASSERT_EQ(resolvedRole, param.role);
    ASSERT_EQ(roleSource, SCF_RBAC_ROLE_SRC_MAPPING);
    ASSERT_EQ(SCF_EnableRbac(ctx_, true), SCF_SUCCESS);

    const bool validRuleResource = param.resourceType != 0 && (param.resourceType & ~SCF_RES_TYPE_ALL) == 0;
    const uint32_t actionBitmap = static_cast<uint32_t>(param.action);
    const bool validRuleAction = actionBitmap != 0 &&
        (actionBitmap & ~(SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE)) == 0;
    const bool validEffect = param.effect == SCF_POLICY_EFFECT_ALLOW || param.effect == SCF_POLICY_EFFECT_DENY;
    const bool validRule = validPolicyTarget && validRuleResource && validRuleAction && validEffect;

    uint32_t ruleId = 0;
    const int32_t addResult = SCF_AddPolicyRule(ctx_, param.subjectNodeId.c_str(), param.targetNodeId.c_str(),
        param.resourceType, actionBitmap, param.effect, &ruleId);
    EXPECT_EQ(addResult,
        validRule ? SCF_SUCCESS : static_cast<int32_t>(SCF_ERRNO_RBAC_POLICY_INVALID));
    EXPECT_EQ(ruleId != 0, validRule);

    const int32_t permissionResult = SCF_CheckResourcePermission(ctx_, cert, param.targetNodeId.c_str(),
        param.resourceType, param.action);
    if (!validPermissionTarget || !validPermissionResource || !validPermissionAction) {
        EXPECT_EQ(permissionResult, SCF_ERRNO_INVALID_PARAM);
    } else if (validRule) {
        EXPECT_EQ(permissionResult,
            param.effect == SCF_POLICY_EFFECT_ALLOW ? SCF_SUCCESS : static_cast<int32_t>(SCF_ERRNO_RBAC_DENIED));
    } else {
        const bool defaultAllow = param.role == SCF_RBAC_ROLE_MASTER || param.targetNodeId == param.subjectNodeId;
        EXPECT_EQ(permissionResult,
            defaultAllow ? SCF_SUCCESS : static_cast<int32_t>(SCF_ERRNO_RBAC_DENIED));
    }
    if (validRule) {
        EXPECT_EQ(SCF_RemovePolicyRule(ctx_, ruleId), SCF_SUCCESS);
    }
}

INSTANTIATE_TEST_SUITE_P(AsteriskOrdinaryAndAllOtherBoundaries, TestRbacSubjectPermissionCombinations,
    ::testing::ValuesIn(MakeSubjectPermissionCombinationParams()));

TEST_P(TestRbacPolicyCacheCases, StoresReadsAndRemovesOneIndependentBoundaryCase)
{
    const PolicyCacheCaseParam &param = GetParam();
    uint32_t ruleId = 0;
    ASSERT_EQ(SCF_AddPolicyRule(ctx_, param.subjectNodeId.c_str(), param.targetNodeId.c_str(),
        param.resourceTypeBitmap, param.actionBitmap, param.effect, &ruleId), param.expected);
    if (param.expected != SCF_SUCCESS) {
        EXPECT_EQ(ruleId, 0U);
        return;
    }
    EXPECT_NE(ruleId, 0U);

    SCF_PolicyRule snapshot[1];
    uint32_t actualCount = 0;
    ASSERT_EQ(SCF_ListPolicyRules(ctx_, snapshot, 1, &actualCount), SCF_SUCCESS);
    ASSERT_EQ(actualCount, 1U);
    EXPECT_EQ(snapshot[0].ruleId, ruleId);
    EXPECT_EQ(snapshot[0].subjectNodeId, param.subjectNodeId);
    EXPECT_EQ(snapshot[0].targetNodeId, param.targetNodeId);
    EXPECT_EQ(snapshot[0].resourceTypeBitmap, param.resourceTypeBitmap);
    EXPECT_EQ(snapshot[0].actionBitmap, param.actionBitmap);
    EXPECT_EQ(snapshot[0].effect, param.effect);

    ASSERT_EQ(SCF_RemovePolicyRule(ctx_, ruleId), SCF_SUCCESS);
    actualCount = 1;
    EXPECT_EQ(SCF_ListPolicyRules(ctx_, snapshot, 1, &actualCount), SCF_SUCCESS);
    EXPECT_EQ(actualCount, 0U);
    EXPECT_EQ(SCF_RemovePolicyRule(ctx_, ruleId), SCF_ERRNO_RBAC_POLICY_NOT_FOUND);
}

INSTANTIATE_TEST_SUITE_P(OneThousandAdditionalPolicyCacheCases, TestRbacPolicyCacheCases,
    ::testing::ValuesIn(MakeOneThousandPolicyCacheParams()));
} // namespace test
