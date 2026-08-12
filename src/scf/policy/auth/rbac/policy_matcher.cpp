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

#include "policy_matcher.h"

namespace scf {
static bool IsRuleMatched(const SCF_PolicyRule &rule, const char *subjectNodeId, const char *targetNodeId,
    uint32_t resourceType, SCF_RESOURCE_ACTION action)
{
    return rule.subjectNodeId == subjectNodeId && (rule.targetNodeId == targetNodeId || rule.targetNodeId == "*") &&
           (rule.resourceTypeBitmap & resourceType) != 0 && (rule.actionBitmap & static_cast<uint32_t>(action)) != 0;
}

static uint32_t GetMatchPriority(
    const SCF_PolicyRule &rule, const char *targetNodeId, uint32_t resourceType, SCF_RESOURCE_ACTION action)
{
    // 匹配规则的优先级从 1 开始，精确匹配的字段越多，优先级越高。
    uint32_t priority = 1;
    if (rule.targetNodeId == targetNodeId) {
        ++priority;
    }
    if (rule.resourceTypeBitmap == resourceType) {
        ++priority;
    }
    if (rule.actionBitmap == static_cast<uint32_t>(action)) {
        ++priority;
    }
    return priority;
}

static bool ShouldReplaceMatch(uint32_t priority, SCF_POLICY_EFFECT effect, uint32_t highestPriority)
{
    return priority > highestPriority || (priority == highestPriority && effect == SCF_POLICY_EFFECT_DENY);
}

bool MatchPolicyRule(const std::map<uint32_t, SCF_PolicyRule> &rules, const char *subjectNodeId,
    const char *targetNodeId, uint32_t resourceType, SCF_RESOURCE_ACTION action, SCF_POLICY_EFFECT *effect)
{
    uint32_t highestPriority = 0;
    for (const auto &item : rules) {
        const auto &rule = item.second;
        if (!IsRuleMatched(rule, subjectNodeId, targetNodeId, resourceType, action)) {
            continue;
        }
        uint32_t priority = GetMatchPriority(rule, targetNodeId, resourceType, action);
        if (!ShouldReplaceMatch(priority, rule.effect, highestPriority)) {
            continue;
        }
        highestPriority = priority;
        *effect = rule.effect;
    }
    return highestPriority != 0;
}
} // namespace scf