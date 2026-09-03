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
#include "custom_logger.h"

namespace scf {
static bool IsRuleMatched(const SCF_PolicyRule &rule, const PolicyMatchRequest &request)
{
    return rule.subjectNodeId == request.subjectNodeId &&
           (rule.targetNodeId == request.targetNodeId || rule.targetNodeId == "*") &&
           (rule.resourceTypeBitmap & request.resourceType) != 0 &&
           (rule.actionBitmap & static_cast<uint32_t>(request.action)) != 0;
}

static uint32_t GetMatchPriority(const SCF_PolicyRule &rule, const PolicyMatchRequest &request)
{
    // 匹配规则的优先级从 1 开始，精确匹配的字段越多，优先级越高。
    uint32_t priority = 1;
    if (rule.targetNodeId == request.targetNodeId) {
        ++priority;
    }
    if (rule.resourceTypeBitmap == request.resourceType) {
        ++priority;
    }
    if (rule.actionBitmap == static_cast<uint32_t>(request.action)) {
        ++priority;
    }
    return priority;
}

static bool ShouldReplaceMatch(uint32_t priority, SCF_POLICY_EFFECT effect, uint32_t highestPriority)
{
    return priority > highestPriority || (priority == highestPriority && effect == SCF_POLICY_EFFECT_DENY);
}

bool MatchPolicyRule(
    const std::map<uint32_t, SCF_PolicyRule> &rules, const PolicyMatchRequest &request, SCF_POLICY_EFFECT *effect)
{
    if (effect == nullptr) {
        CCSEC_LOG_ERROR("|bool MatchPolicyRule(|END|returnF||effect is nullptr.");
        return false;
    }
    uint32_t highestPriority = 0;
    for (const auto &item : rules) {
        const auto &rule = item.second;
        if (!IsRuleMatched(rule, request)) {
            continue;
        }
        uint32_t priority = GetMatchPriority(rule, request);
        if (!ShouldReplaceMatch(priority, rule.effect, highestPriority)) {
            continue;
        }
        highestPriority = priority;
        *effect = rule.effect;
    }
    return highestPriority != 0;
}
} // namespace scf