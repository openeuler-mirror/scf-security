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

#ifndef SCF_POLICY_MATCHER_H
#define SCF_POLICY_MATCHER_H

#include <map>

#include "scf_def.h"

namespace scf {
/**
 * @brief 描述一次自定义策略规则匹配所需的请求属性。
 */
struct PolicyMatchRequest {
    const char *subjectNodeId;  // 发起操作的节点 ID
    const char *targetNodeId;   // 目标资源所属节点 ID
    uint32_t resourceType;      // 单个资源类型
    SCF_RESOURCE_ACTION action; // 单个资源动作
};

/**
 * @brief 查找优先级最高的自定义策略规则。
 * @param rules [IN] 待匹配的自定义策略规则。
 * @param request [IN] 待鉴权的主体、目标、资源类型和动作。
 * @param effect [OUT] 命中规则的效果；未命中时保持不变。
 * @return 命中规则返回 true，否则返回 false。
 * @attention 调用方必须持有 rules 对应的策略规则锁。
 */
bool MatchPolicyRule(
    const std::map<uint32_t, SCF_PolicyRule> &rules, const PolicyMatchRequest &request, SCF_POLICY_EFFECT *effect);
} // namespace scf

#endif // SCF_POLICY_MATCHER_H