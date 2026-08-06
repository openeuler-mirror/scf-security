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

#include <cstring>
#include <new>
#include <limits>
#include "custom_logger.h"
#include "scf.h"
#include "scf_inner.h"
#include "securec.h"
#include "string_util.h"

namespace scf {
static bool IsValidNodeId(const char *nodeId)
{
    if (nodeId == nullptr) {
        return false;
    }
    size_t length = strnlen(nodeId, MAX_NODE_ID_LEN);
    return length > 0 && length < MAX_NODE_ID_LEN;
}

static bool IsValidRole(SCF_RBAC_ROLE role)
{
    return role == SCF_RBAC_ROLE_MASTER || role == SCF_RBAC_ROLE_SLAVE;
}

static bool IsValidBitmap(uint32_t bitmap, uint32_t validBitmap)
{
    return bitmap != 0 && (bitmap & ~validBitmap) == 0;
}

static bool IsValidPolicyEffect(SCF_POLICY_EFFECT effect)
{
    return effect == SCF_POLICY_EFFECT_ALLOW || effect == SCF_POLICY_EFFECT_DENY;
}

static bool IsDuplicatePolicyRule(const SCF_PolicyRule &left, const SCF_PolicyRule &right)
{
    return left.subjectNodeId == right.subjectNodeId && left.targetNodeId == right.targetNodeId &&
        left.resourceTypeBitmap == right.resourceTypeBitmap && left.actionBitmap == right.actionBitmap &&
        left.effect == right.effect;
}

void FreezeNodeRoleMapping(SCF_PolicyCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(ctx->nodeRoleMapMutex);
    if (!ctx->nodeRoleMapFrozen.exchange(true)) {
        CCSEC_LOG_DEBUG("|FreezeNodeRoleMapping|END|returnS||node role mapping is frozen after connection established");
    }
}

static int32_t GetMappingRole(SCF_PolicyCtx *ctx, const char *nodeId, SCF_RBAC_ROLE *role)
{
    if (!IsValidNodeId(nodeId)) {
        return SCF_ERRNO_RBAC_ROLE_UNKNOWN;
    }
    // 映射表读写均由同一互斥锁保护。
    std::lock_guard<std::mutex> lock(ctx->nodeRoleMapMutex);
    auto it = ctx->nodeRoleMap.find(nodeId);
    if (it == ctx->nodeRoleMap.end()) {
        return SCF_ERRNO_RBAC_ROLE_UNKNOWN;
    }
    *role = it->second;
    return SCF_SUCCESS;
}

int32_t SCF_GetCertNodeId(const void *cert, char *nodeIdBuffer, size_t bufferLen, size_t *nodeIdLen)
{
    if (cert == nullptr || nodeIdBuffer == nullptr || nodeIdLen == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (bufferLen == 0) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||buffer is too short");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_GetCertNodeId");
    CHECK_SCF_ADAPTOR_RET("SCF_GetCertNodeId");
    std::string nodeId;
    int32_t ret = g_adaptor->GetCertExtensionByOid(cert, SCF_OID_NODE_ID, nodeId);
    if (ret == SCF_SSL_ERR_CERT_EXT_ABSENT) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||node id extension is absent");
        return SCF_ERRNO_CERT_NODE_ID_ABSENT;
    }
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||read node id extension failed, ret:" << ret);
        return ret;
    }
    if (nodeId.empty() || nodeId.size() >= MAX_NODE_ID_LEN || nodeId.find('\0') != std::string::npos) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||node id extension is invalid");
        return SCF_SSL_ERR_PARSE_CERT;
    }
    if (nodeId.size() >= bufferLen) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||buffer is too short");
        return SCF_ERRNO_INVALID_PARAM;
    }
    if (memcpy_s(nodeIdBuffer, bufferLen, nodeId.data(), nodeId.size()) != EOK) {
        CCSEC_LOG_ERROR("|SCF_GetCertNodeId|END|returnF||copy node id failed");
        return SCF_ERRNO_MEM_CPY;
    }
    nodeIdBuffer[nodeId.size()] = '\0';
    *nodeIdLen = nodeId.size();
    CCSEC_LOG_DEBUG("|SCF_GetCertNodeId|END|returnS||get certificate node id success");
    return SCF_SUCCESS;
}

int32_t SCF_GetCertRbacRole(const void *cert, SCF_RBAC_ROLE *role)
{
    if (cert == nullptr || role == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetCertRbacRole|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_GetCertRbacRole");
    CHECK_SCF_ADAPTOR_RET("SCF_GetCertRbacRole");
    std::string value;
    int32_t ret = g_adaptor->GetCertExtensionByOid(cert, SCF_OID_RBAC_ROLE, value);
    if (ret == SCF_SSL_ERR_CERT_EXT_ABSENT) {
        CCSEC_LOG_ERROR("|SCF_GetCertRbacRole|END|returnF||role extension is absent");
        return SCF_ERRNO_CERT_ROLE_EXT_ABSENT;
    }
    if (ret != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_GetCertRbacRole|END|returnF||read role extension failed, ret:" << ret);
        return ret;
    }
    value = ToLower(value);
    if (value == "master") {
        *role = SCF_RBAC_ROLE_MASTER;
        CCSEC_LOG_DEBUG("|SCF_GetCertRbacRole|END|returnS||get certificate role success");
        return SCF_SUCCESS;
    }
    if (value == "slave") {
        *role = SCF_RBAC_ROLE_SLAVE;
        CCSEC_LOG_DEBUG("|SCF_GetCertRbacRole|END|returnS||get certificate role success");
        return SCF_SUCCESS;
    }
    CCSEC_LOG_ERROR("|SCF_GetCertRbacRole|END|returnF||role extension is invalid");
    return SCF_SSL_ERR_PARSE_CERT;
}

int32_t SCF_SetNodeRoleMapping(SCF_PolicyCtx *ctx, const char *nodeId, SCF_RBAC_ROLE role)
{
    if (ctx == nullptr || nodeId == nullptr) {
        CCSEC_LOG_ERROR("|SCF_SetNodeRoleMapping|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (!IsValidNodeId(nodeId) || !IsValidRole(role)) {
        CCSEC_LOG_ERROR("|SCF_SetNodeRoleMapping|END|returnF||invalid node id or role");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_SetNodeRoleMapping");
    std::lock_guard<std::mutex> lock(ctx->nodeRoleMapMutex);
    if (ctx->nodeRoleMapFrozen.load()) {
        CCSEC_LOG_ERROR("|SCF_SetNodeRoleMapping|END|returnF||node role mapping is frozen");
        return SCF_ERRNO_RBAC_MAP_FROZEN;
    }
    auto it = ctx->nodeRoleMap.find(nodeId);
    if (it == ctx->nodeRoleMap.end() && ctx->nodeRoleMap.size() >= MAX_NODE_ROLE_MAP_SIZE) {
        CCSEC_LOG_ERROR("|SCF_SetNodeRoleMapping|END|returnF||node role map is full");
        return SCF_ERRNO_RBAC_MAP_FULL;
    }
    try {
        ctx->nodeRoleMap[nodeId] = role;
    } catch (const std::bad_alloc &) {
        CCSEC_LOG_ERROR("|SCF_SetNodeRoleMapping|END|returnF||memory allocation failed");
        return SCF_ERRNO_MEM_ALLOC;
    }
    CCSEC_LOG_DEBUG("|SCF_SetNodeRoleMapping|END|returnS||set node role mapping success");
    return SCF_SUCCESS;
}

int32_t SCF_RemoveNodeRoleMapping(SCF_PolicyCtx *ctx, const char *nodeId)
{
    if (ctx == nullptr || nodeId == nullptr) {
        CCSEC_LOG_ERROR("|SCF_RemoveNodeRoleMapping|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (!IsValidNodeId(nodeId)) {
        CCSEC_LOG_ERROR("|SCF_RemoveNodeRoleMapping|END|returnF||invalid node id");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_RemoveNodeRoleMapping");
    std::lock_guard<std::mutex> lock(ctx->nodeRoleMapMutex);
    if (ctx->nodeRoleMapFrozen.load()) {
        CCSEC_LOG_ERROR("|SCF_RemoveNodeRoleMapping|END|returnF||node role mapping is frozen");
        return SCF_ERRNO_RBAC_MAP_FROZEN;
    }
    if (ctx->nodeRoleMap.erase(nodeId) == 0) {
        CCSEC_LOG_ERROR("|SCF_RemoveNodeRoleMapping|END|returnF||node role mapping is absent");
        return SCF_ERRNO_RBAC_MAP_NOT_FOUND;
    }
    CCSEC_LOG_DEBUG("|SCF_RemoveNodeRoleMapping|END|returnS||remove node role mapping success");
    return SCF_SUCCESS;
}

int32_t SCF_GetNodeRbacRole(SCF_PolicyCtx *ctx, const void *cert, const char *nodeId, SCF_RBAC_ROLE *role,
    SCF_RBAC_ROLE_SOURCE *src)
{
    if (ctx == nullptr || (cert == nullptr && nodeId == nullptr) || role == nullptr || src == nullptr) {
        CCSEC_LOG_ERROR("|SCF_GetNodeRbacRole|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (nodeId != nullptr && !IsValidNodeId(nodeId)) {
        CCSEC_LOG_ERROR("|SCF_GetNodeRbacRole|END|returnF||invalid node id");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_GetNodeRbacRole");
    *role = SCF_RBAC_ROLE_UNKNOWN;
    *src = SCF_RBAC_ROLE_SRC_NONE;
    const char *mappingNodeId = nodeId;
    char certNodeId[MAX_NODE_ID_LEN] = {0};
    if (cert != nullptr) {
        SCF_RBAC_ROLE certRole = SCF_RBAC_ROLE_UNKNOWN;
        int32_t certRoleRet = SCF_GetCertRbacRole(cert, &certRole);
        if (certRoleRet != SCF_SUCCESS && certRoleRet != SCF_ERRNO_CERT_ROLE_EXT_ABSENT) {
            CCSEC_LOG_ERROR("|SCF_GetNodeRbacRole|END|returnF||get certificate role failed, ret:" << certRoleRet);
            return certRoleRet;
        }
        size_t certNodeIdLen = 0;
        int32_t certNodeIdRet = SCF_GetCertNodeId(cert, certNodeId, sizeof(certNodeId), &certNodeIdLen);
        if (certNodeIdRet == SCF_SUCCESS) {
            mappingNodeId = certNodeId;
        } else if (certNodeIdRet != SCF_ERRNO_CERT_NODE_ID_ABSENT) {
            CCSEC_LOG_ERROR("|SCF_GetNodeRbacRole|END|returnF||get certificate node id failed, ret:" << certNodeIdRet);
            return certNodeIdRet;
        }
        if (certRoleRet == SCF_SUCCESS) {
            *role = certRole;
            *src = SCF_RBAC_ROLE_SRC_CERT;
            CCSEC_LOG_DEBUG("|SCF_GetNodeRbacRole|END|returnS||get node role from certificate success");
            return SCF_SUCCESS;
        }
    }
    if (GetMappingRole(ctx, mappingNodeId, role) != SCF_SUCCESS) {
        CCSEC_LOG_ERROR("|SCF_GetNodeRbacRole|END|returnF||role is unknown");
        return SCF_ERRNO_RBAC_ROLE_UNKNOWN;
    }
    *src = SCF_RBAC_ROLE_SRC_MAPPING;
    CCSEC_LOG_DEBUG("|SCF_GetNodeRbacRole|END|returnS||get node role from mapping success");
    return SCF_SUCCESS;
}

int32_t SCF_EnableRbac(SCF_PolicyCtx *ctx, bool enable)
{
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_EnableRbac|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    CHECK_SCF_INIT_RET("SCF_EnableRbac");
    ctx->rbacEnabled.store(enable);
    CCSEC_LOG_DEBUG("|SCF_EnableRbac|END|returnS||set RBAC status success");
    return SCF_SUCCESS;
}

int32_t SCF_ListMasterNodes(SCF_PolicyCtx *ctx, char nodeIdList[][MAX_NODE_ID_LEN], uint32_t listCap,
    uint32_t *actualCount)
{
    if (ctx == nullptr || nodeIdList == nullptr || actualCount == nullptr) {
        CCSEC_LOG_ERROR("|SCF_ListMasterNodes|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (listCap == 0) {
        CCSEC_LOG_ERROR("|SCF_ListMasterNodes|END|returnF||list capacity is zero");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_ListMasterNodes");
    *actualCount = 0;
    std::lock_guard<std::mutex> lock(ctx->nodeRoleMapMutex);
    for (const auto &mapping : ctx->nodeRoleMap) {
        if (mapping.second != SCF_RBAC_ROLE_MASTER || *actualCount == listCap) {
            continue;
        }
        if (memcpy_s(nodeIdList[*actualCount], MAX_NODE_ID_LEN, mapping.first.data(), mapping.first.size()) != EOK) {
            CCSEC_LOG_ERROR("|SCF_ListMasterNodes|END|returnF||copy node id failed");
            return SCF_ERROR;
        }
        nodeIdList[*actualCount][mapping.first.size()] = '\0';
        ++(*actualCount);
    }
    CCSEC_LOG_DEBUG("|SCF_ListMasterNodes|END|returnS||list master nodes success");
    return SCF_SUCCESS;
}

int32_t SCF_IsMasterNode(SCF_PolicyCtx *ctx, const char *nodeId, bool *isMaster)
{
    if (ctx == nullptr || nodeId == nullptr || isMaster == nullptr) {
        CCSEC_LOG_ERROR("|SCF_IsMasterNode|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (!IsValidNodeId(nodeId)) {
        CCSEC_LOG_ERROR("|SCF_IsMasterNode|END|returnF||invalid node id");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_IsMasterNode");
    std::lock_guard<std::mutex> lock(ctx->nodeRoleMapMutex);
    auto it = ctx->nodeRoleMap.find(nodeId);
    *isMaster = it != ctx->nodeRoleMap.end() && it->second == SCF_RBAC_ROLE_MASTER;
    CCSEC_LOG_DEBUG("|SCF_IsMasterNode|END|returnS||check master node success");
    return SCF_SUCCESS;
}

int32_t SCF_AddPolicyRule(SCF_PolicyCtx *ctx, const char *subjectNodeId, const char *targetNodeId,
    uint32_t resourceTypeBitmap, uint32_t actionBitmap, SCF_POLICY_EFFECT effect, uint32_t *ruleId)
{
    if (ctx == nullptr || subjectNodeId == nullptr || targetNodeId == nullptr || ruleId == nullptr) {
        CCSEC_LOG_ERROR("|SCF_AddPolicyRule|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (!IsValidNodeId(subjectNodeId) || std::strcmp(subjectNodeId, "*") == 0 || !IsValidNodeId(targetNodeId) ||
        !IsValidBitmap(resourceTypeBitmap, SCF_RES_TYPE_ALL) ||
        !IsValidBitmap(actionBitmap, SCF_RES_ACTION_APPLY | SCF_RES_ACTION_RELEASE) || !IsValidPolicyEffect(effect)) {
        CCSEC_LOG_ERROR("|SCF_AddPolicyRule|END|returnF||invalid policy rule");
        return SCF_ERRNO_RBAC_POLICY_INVALID;
    }
    CHECK_SCF_INIT_RET("SCF_AddPolicyRule");
    SCF_PolicyRule rule = {0, subjectNodeId, targetNodeId, resourceTypeBitmap, actionBitmap, effect};
    std::lock_guard<std::mutex> lock(ctx->policyRuleMutex);
    for (const auto &item : ctx->policyRuleList) {
        if (IsDuplicatePolicyRule(item, rule)) {
            CCSEC_LOG_ERROR("|SCF_AddPolicyRule|END|returnF||duplicate policy rule");
            return SCF_ERRNO_RBAC_POLICY_DUPLICATE;
        }
    }
    if (ctx->policyRuleList.size() >= MAX_POLICY_RULE_SIZE || ctx->nextPolicyRuleId == 0) {
        CCSEC_LOG_ERROR("|SCF_AddPolicyRule|END|returnF||policy rule list is full");
        return SCF_ERRNO_RBAC_POLICY_FULL;
    }
    rule.ruleId = ctx->nextPolicyRuleId;
    if (ctx->nextPolicyRuleId == std::numeric_limits<uint32_t>::max()) {
        ctx->nextPolicyRuleId = 0;
    } else {
        ++ctx->nextPolicyRuleId;
    }
    ctx->policyRuleList.push_back(rule);
    *ruleId = rule.ruleId;
    CCSEC_LOG_DEBUG("|SCF_AddPolicyRule|END|returnS||add policy rule success");
    return SCF_SUCCESS;
}

int32_t SCF_RemovePolicyRule(SCF_PolicyCtx *ctx, uint32_t ruleId)
{
    if (ctx == nullptr) {
        CCSEC_LOG_ERROR("|SCF_RemovePolicyRule|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (ruleId == 0) {
        CCSEC_LOG_ERROR("|SCF_RemovePolicyRule|END|returnF||invalid rule id");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_RemovePolicyRule");
    std::lock_guard<std::mutex> lock(ctx->policyRuleMutex);
    for (auto it = ctx->policyRuleList.begin(); it != ctx->policyRuleList.end(); ++it) {
        if (it->ruleId == ruleId) {
            ctx->policyRuleList.erase(it);
            CCSEC_LOG_DEBUG("|SCF_RemovePolicyRule|END|returnS||remove policy rule success");
            return SCF_SUCCESS;
        }
    }
    CCSEC_LOG_ERROR("|SCF_RemovePolicyRule|END|returnF||policy rule is absent");
    return SCF_ERRNO_RBAC_POLICY_NOT_FOUND;
}

int32_t SCF_ListPolicyRules(SCF_PolicyCtx *ctx, SCF_PolicyRule *rules, uint32_t ruleCap, uint32_t *actualCount)
{
    if (ctx == nullptr || rules == nullptr || actualCount == nullptr) {
        CCSEC_LOG_ERROR("|SCF_ListPolicyRules|END|returnF||null input");
        return SCF_ERRNO_NULL_INPUT;
    }
    if (ruleCap == 0) {
        CCSEC_LOG_ERROR("|SCF_ListPolicyRules|END|returnF||rule capacity is zero");
        return SCF_ERRNO_INVALID_PARAM;
    }
    CHECK_SCF_INIT_RET("SCF_ListPolicyRules");
    *actualCount = 0;
    std::lock_guard<std::mutex> lock(ctx->policyRuleMutex);
    for (const auto &rule : ctx->policyRuleList) {
        if (*actualCount == ruleCap) {
            break;
        }
        rules[*actualCount] = rule;
        ++(*actualCount);
    }
    CCSEC_LOG_DEBUG("|SCF_ListPolicyRules|END|returnS||list policy rules success");
    return SCF_SUCCESS;
}
}