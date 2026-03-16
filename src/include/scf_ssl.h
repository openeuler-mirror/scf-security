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


#ifndef SCF_SSL_H
#define SCF_SSL_H

#include <stdint.h>
#include <stddef.h>
#include "scf_def.h"

#ifdef __cplusplus
extern "C" {
#endif

namespace scf {
/**
 * @ingroup scf
 * @brief  创建 SSL 会话对象
 * @return 异常返回 NULL，成功则返回 SCF_Session 对象
 */
SCF_Session *SCF_SessionNew(void);

/**
 * @ingroup scf
 * @brief  释放 SSL 会话对象
 * @param  sess [IN] SSL 会话对象
 * @return void
 */
void SCF_SessionFree(SCF_Session **sess);

/**
 * @ingroup scf
 * @brief  配置服务端 TLS 1.3 psk 回调
 * @param  ctx [IN] 安全策略上下文
 * @param  cb [IN] psk 回调。可以为 NULL
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetPskFindSessionCallback(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb);

/**
 * @ingroup scf
 * @brief  配置客户端 TLS 1.3 psk 回调
 * @param  ctx [IN] 安全策略上下文
 * @param  cb [IN] psk 回调。可以为 NULL
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetPskUseSessionCallback(SCF_PolicyCtx *ctx, SCF_PskUseSessionCb cb);

/**
 * @ingroup scf
 * @brief  配置 SSL 会话对象的 master key
 * @param sess [IN] SSL 会话对象
 * @param masterKey[IN] 密钥物料。通信PSK会基于此物料派生, 需要调用方释放内存
 * @param masterKeyLen[IN] 密钥物料长度
 * @param isCipher [IN] 是否为密文
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SessionSetMasterKey(SCF_Session *sess, const uint8_t *masterKey, size_t masterKeyLen,
                                bool isCipher = false);

/**
 * @ingroup scf
 * @brief  配置 SSL 会话对象的算法套
 * @param  sess [IN] SSL 会话对象
 * @param  cipherSuite [IN] TLS 算法套数组
 * @param  cipherLen [IN] TLS 算法套数组长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SessionSetCipher(SCF_Session *sess, const void *cipherSuite, size_t cipherLen);

/**
 * @ingroup scf
 * @brief  获取 SSL 会话对象的算法套
 * @param  sess [IN] SSL 会话对象
 * @param  cipherSuite [OUT] TLS 算法套数组--使用完成后需要调用SCF_SessionFreeCipher进行资源释放
 * @param  cipherLen [OUT] TLS 算法套数组长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SessionGetCipher(SCF_Session *sess, void **cipherSuite, size_t &cipherLen);

/**
 * @ingroup scf
 * @brief  释放 SSL 会话对象的算法套
 * @param  cipherSuite [IN] TLS 算法套数组
 * @param  cipherLen [IN] TLS 算法套数组长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
void SCF_SessionFreeCipher(void **cipherSuite, size_t &cipherLen);

/**
 * @ingroup scf
 * @brief  配置 SSL 会话对象的协议版本
 * @param  sess [IN] SSL 会话对象
 * @param  version [IN] 协议版本
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SessionSetProtocolVersion(SCF_Session *sess, const char *version);

/**
 * @ingroup scf
 * @brief  获取 SSL 会话对象的协议版本
 * @param  sess [IN] SSL 会话对象
 * @param  version [OUT] 协议版本--使用完成后需要调用SCF_FreeBuffer进行资源释放
 * @param  versionLen [OUT] 协议版本内容长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen);

/**
 * @ingroup scf
 * @brief  查找算法套对象，适配OPENSSL设置算法套
 * @param  obj [IN] SCF 策略上下文
 * @param  cipherId [IN] 算法套 id 对象
 * @return 算法套对象
 */
const void *SCF_CipherFind(SCF_PolicyObj *obj, uint8_t *cipherId);

// 安全链路更新
/**
 * @ingroup scf
 * @brief  设置密钥更新的流量和时间阈值
 * @param ctx 安全策略上下文
 * @param isNeedKeyUpdate [IN] true = 启用，false = 关闭。
 * @param  keyUpdateTime [IN] 达到此间隔时间后，更新密钥。范围 [1, 31536000]，单位 秒。
 * @param  keyUpdateTraffic [IN] 达到此流量后，更新密钥。范围 [1000, uint64_max]。单位 byte,，建议实际使用场景不低于1000000byte(1GB)。
 * @attention  keyUpdateTime 和 keyUpdateTraffic 当isNeedKeyUpdate 为true时会做校验，为false时不做校验也不生效。
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetKeyAutoUpdateParam(
    SCF_PolicyCtx *ctx, bool isNeedKeyUpdate, uint32_t keyUpdateTime, uint64_t keyUpdateTraffic);

/**
 * @ingroup scf
 * @brief  获取密钥更新的流量和时间阈值
 * @param ctx 安全策略上下文
 * @param isNeedKeyUpdate [OUT] true = 启用，false = 关闭。
 * @param  keyUpdateTime [OUT] 达到此间隔时间后，更新密钥。范围 [1, 31536000]，单位 秒。
 * @param  keyUpdateTraffic [OUT] 达到此流量后，更新密钥。范围 [1000, uint64_max]。单位 byte,，建议实际使用场景不低于1000000byte(1GB)。
 * @attention  keyUpdateTime 和 keyUpdateTraffic 当isNeedKeyUpdate 为true时会有意义，为false时无实际意义。
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_GetKeyAutoUpdateParam(
    SCF_PolicyCtx *ctx, bool &isNeedKeyUpdate, uint32_t &keyUpdateTime, uint64_t &keyUpdateTraffic);

/**
 * @ingroup scf
 * @brief 主动触发当前链路的 keyupdate
 * @param obj [IN] 安全策略对象实例
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_ObjKeyUpdate(SCF_PolicyObj *obj);

/**
 * @ingroup scf
 * @brief  获取密钥相关的信息
 * @param  obj [IN] 安全策略对象实例
 * @param  lastKeyUpdateTime [OUT] 上次主动更新密钥时间
 * @param  timeInterval [OUT] 更新时间周期
 * @param  remainTraffic [OUT] 距离下次主动更新密钥的剩余写流量
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_GetKeyUpdateInfo(SCF_PolicyObj *obj, uint64_t *lastKeyUpdateTime,
    uint32_t *timeInterval, uint64_t *remainTraffic);

/**
 * @ingroup spc
 * @brief  设置用户自定义数据
 * @param  obj [IN] 安全策略上下文
 * @param  userData [IN] 指向用户自定义数据的指针
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetUserData(SCF_PolicyObj *obj, void *userData);

/**
 * @ingroup spc
 * @brief  获取用户自定义数据
 * @param  obj [IN] 安全策略上下文
 * @return 指向用户自定义数据的指针，失败返回 NULL
 */
void *SCF_GetUserData(SCF_PolicyObj *obj);
}

#ifdef __cplusplus
}
#endif

#endif