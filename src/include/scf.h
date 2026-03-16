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

#ifndef SCF_H
#define SCF_H

#include <stddef.h>
#include <stdint.h>

#include "scf_def.h"

#ifdef __cplusplus
extern "C" {
#endif

namespace scf {
/**
 * @ingroup scf
 * @brief  初始化 SCF 模块
 * @param  flag [IN] 初始化选项
 * @param  setttings [IN] 初始化配置。为扩展兼容不同底层实现预留，当前直接传 NULL 即可。
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_Init(uint64_t flag, void *settings);

/**
 * @ingroup scf
 * @brief  去初始化 SCF 模块
 * @return void
 */
void SCF_DeInit(void);

/**
 * @ingroup scf
 * @brief  释放查询接口返回的buffer资源
 * @param  buffer      [IN] 需要清理的资源
 * @param  bufferLen   [IN] 需要清理的资源长度
 */
void SCF_FreeBuffer(char **buffer, size_t &bufferLen);

/**
 * @ingroup scf
 * @brief  获取错误码对应的信息
 * @return 错误信息
 */
const char *GetErrorMessage(int32_t errorCode);

/**
 * @ingroup scf
 * @brief  设置自定义日志函数
 * @return void
 */
void SetExternalLogFunction(ExternalLogFunction func);

/**
 * @ingroup scf
 * @brief  设置自定义解密函数
 * @return void
 */
void SetExternalDecryptFunction(ExternalDecryptFunction func);

/**
 * @ingroup scf
 * @brief  创建文件上下文
 * @return 失败返回 NULL，成功返回文件上下文
 */
SCF_FILE_CTX *SCF_FileCtxNew(void);

/**
 * @ingroup scf
 * @brief  释放 SCF_FILE_CTX 对象的内存，与 SCF_FileCtxNew 配对使用
 * @param ctx [IN] 文件上下文
 * @return void
 */
void SCF_FileCtxFree(SCF_FILE_CTX **ctx);

/**
 * @ingroup scf
 * @brief  配置存储的信息
 * @param ctx [IN] 文件上下文
 * @param storeType [IN] 数据存储方式类型
 * @param buf [IN] 数据内容。根据 storeType 不同，应该分别是文件路径/buffer/标识符等
 * @param bufLen [IN] buf 的长度。文件路径时，最大路径长度为4096（有效长度4095 + '\0'结束符）
 * @param format [IN] 数据存储的格式
 * @return 失败返回错误码，成功返回 SCF_SUCCESS
 * @attention ctx 需要提前使用 SCF_FileCtxNew 创建
 * @attention 数据内容为文件路径时，用户需要保证是绝对路径和文件有效性
 */
int32_t SCF_FileCtxSetBuf(
    SCF_FILE_CTX *ctx, SCF_STORE_TYPE storeType, uint8_t *buf, size_t bufLen, SCF_STORE_FORMAT format);

/**
 * @ingroup scf
 * @brief  设置证书私钥口令
 * @param ctx [IN] 文件上下文
 * @param passwd [IN] 密钥缓冲区，存放口令内容，当是密文的时候，会解密成明文再使用
 * 使用完ctx后，需调用SCF_FileCtxFree接口释放ctx，之后调用方清理passwd内存
 * @param passwdLen [IN] passwd 口令长度
 * @param isCipher  [IN] 是否为密文
 * @return 失败返回错误码，成功返回 SCF_SUCCESS
 */
int32_t SCF_FileCtxSetPwd(SCF_FILE_CTX *ctx, uint8_t *passwd, const size_t passwdLen, bool isCipher = false);

/**
 * @ingroup scf
 * @brief  创建安全策略上下文
 * @return 安全策略上下文，异常返回 NULL
 */
SCF_PolicyCtx *SCF_CreatePolicyCtx(void);

/**
 * @ingroup scf
 * @brief  释放安全通信上下文， 与 SCF_CreatePolicyCtx 配对使用
 * @param  ctx [IN] 安全策略上下文
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
void SCF_FreePolicyCtx(SCF_PolicyCtx **ctx);

// 配置 - 必要
/**
 * @ingroup scf
 * @brief  设置安全通信策略模式
 * @param  ctx [IN] 安全策略上下文
 * @param  role [IN] 通信角色。需要用户指定是作为 client 还是 server。
 * @param  verifyMode [IN] 是否校验对端
 * @param  policyMode [IN] 安全校验策略模式
 * @return 错误码，成功则返回 SCF_SUCCESS
 * @attention 根据安全校验策略模式，会应用默认的安全配置选项。如果业务需要特别指定，可以单独调用配置接口
 */
int32_t SCF_SetPolicy(SCF_PolicyCtx *ctx, SCF_ROLE role, uint32_t verifyMode, SCF_POLICY_MODE policyMode);

/**
 * @ingroup scf
 * @brief  获取安全通信策略模式
 * @param  ctx [IN] 安全策略上下文
 * @param  role [OUT] 通信角色。
 * @param  verifyMode [OUT] 校验对端模式
 * @param  policyMode [OUT] 安全校验策略模式
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_GetPolicy(SCF_PolicyCtx *ctx, SCF_ROLE *role, uint32_t *verifyMode, SCF_POLICY_MODE *policyMode);

/**
 * @ingroup scf
 * @brief  配置安全通信的证书
 * @param  ctx [IN] 安全策略上下文
 * @param  certCtx [IN] 证书上下文
 * @param  type [IN] 证书/CRL 类型
 * @return 错误码，成功则返回 SCF_SUCCESS
 * @attention 如果存在单个文件中有多个 type 对象类型（例如允许同时存在 CA证书/设备证书/CRL），
 * 用户需要先将文件内容按 type 对象分开。对于同一类对象，规格上支持单个 pem 文件有多个 ca 证书，或单个 pem 文件有多个
 * crl 对象。 有多个设备证书时，固定只会取第一个证书作为设备证书。 在函数外释放 certCtx 资源，函数内不包含释放。
 */
int32_t SCF_AddCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type);

/**
 * @ingroup scf
 * @brief  配置安全通信的证书私钥
 * @param  ctx [IN] 安全策略上下文
 * @param  keyCtx [IN] 密钥上下文
 * @return 错误码，成功则返回 SCF_SUCCESS
 * @attention 如果存在单个文件中有多个私钥对象，固定只会取第一个私钥作为设备证书对应的密钥。
 * 不支持混合了证书/公钥/私钥等对象的文件。
 */
int32_t SCF_SetKey(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx);

// 配置 - 可选
/**
 * @ingroup scf
 * @brief  配置安全通信的配置文件
 * @param  ctx [IN] 安全策略上下文
 * @param  config [IN] 配置文件路径
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetConfigFile(SCF_PolicyCtx *ctx, const char *config);

/**
 * @ingroup scf
 * @brief  配置安全通信的校验回调。配置后，内部的证书认证检查会使用用户注册的实现，不使用默认实现。
 * @param  ctx [IN] 安全策略上下文
 * @param  cb [IN] 用户的认证校验实现
 * @param  arg [IN] 用户数据
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetAppVerifyCallback(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg);

/**
 * @ingroup scf
 * @brief  公私钥匹配检查。检查已经加载的证书和密钥是否匹配
 * @param  ctx [IN] 安全策略上下文
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_CheckPrivateKey(SCF_PolicyCtx *ctx);

/**
 * @ingroup scf
 * @brief  获取对端的证书
 * @param  obj [IN] 安全策略对象实例
 * @return 指向对端证书的指针
 */
void *SCF_GetPeerCert(SCF_PolicyObj *obj);

/**
 * @ingroup scf
 * @brief  释放证书对象资源，在SCF_GetPeerCert后使用
 * @param  cert [IN] 指向证书结构体的指针
 */
void SCF_FreeCert(void **cert);

/**
 * @ingroup scf
 * @brief  获取当前会话的证书版本
 * @param  cert [IN] 指向证书结构体的指针
 * @return 证书版本 小于0为异常
 */
int32_t SCF_GetCertVersion(const void *cert);

/**
 * @ingroup scf
 * @brief  获取当前会话的证书生效时间
 * @param  cert [IN] 指向证书结构体的指针
 * @param  certStartTimeBuffer [OUT] 证书开始时间buffer
 * @param  bufferLen [IN] buffer长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_GetCertStartTime(const void *cert, char *certStartTimeBuffer, size_t bufferLen);

/**
 * @ingroup scf
 * @brief  获取当前会话的证书失效时间
 * @param  cert [IN] 指向证书结构体的指针
 * @param  certEndTimeBuffer [OUT] 证书结束时间buffer
 * @param  bufferLen [IN] buffer长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_GetCertEndTime(const void *cert, char *certEndTimeBuffer, size_t bufferLen);

/**
 * @ingroup scf
 * @brief  获取证书的序列号
 * @param  cert [IN] 指向证书结构体的指针
 * @param  dataLen [OUT] 指向序列号结构体长度的指针
 * @return 指向证书的序列号的指针，读完不需要释放
 */
uint8_t *SCF_GetCertSerialNumber(const void *cert, uint32_t *dataLen);

/**
 * @ingroup scf
 * @brief  配置安全通信使用的算法套
 * @param  ctx [IN] 安全策略上下文
 * @param  cipherSuites [IN] 算法套数组
 * @param  cipherSuitesSize [IN] cipherSuites 的数量
 * @return 错误码，成功则返回 SCF_SUCCESS
 * @attention 用户需要将安全性高的作为高优先级套件排在前面。内部实现是根据顺序协商的，优先协商排在前面的。
 */
int32_t SCF_SetCipherSuites(SCF_PolicyCtx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize);

/**
 * @ingroup scf
 * @brief  获取加密算法套
 * @param  ctx [IN] 安全策略上下文
 * @param  data [OUT] 加密算法套的数据
 * @param  dataLen [IN] 缓冲区长度
 * @param  cipherSuitesSize [OUT] 加密算法套的数据长度
 * @return 错误码，成功返回SCF_SUCCESS
 */
int32_t SCF_GetCipherSuites(SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen, uint32_t *cipherSuitesSize);

// obj
/**
 * @ingroup scf
 * @brief  创建安全策略对象实例
 * @param  ctx [IN] 安全策略上下文
 * @return 安全策略对象实例，异常返回 NULL
 */
SCF_PolicyObj *SCF_CreatePolicyObj(SCF_PolicyCtx *ctx);

/**
 * @ingroup scf
 * @brief  释放安全通信对象实例
 * @param  obj [IN] 安全策略对象实例
 * @return void
 */
void SCF_FreePolicyObj(SCF_PolicyObj **obj);

/**
 * @ingroup scf
 * @brief  客户端向服务端发起连接
 * @param  obj [IN] 安全策略对象实例
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_Connect(SCF_PolicyObj *obj);

/**
 * @ingroup scf
 * @brief  服务端等待客户端连接
 * @param  obj [IN] 安全策略对象实例
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_Accept(SCF_PolicyObj *obj);

/**
 * @ingroup scf
 * @brief  关闭安全通信
 * @param  obj [IN] 安全策略对象实例
 * @return 错误码，成功则返回 SCF_SUCCESS
 * @attention 传 NULL 视为已经关闭，返回的是成功
 */
int32_t SCF_Close(SCF_PolicyObj *obj);

/**
 * @ingroup scf
 * @brief  读安全传输数据
 * @param  obj [IN] 安全策略对象实例
 * @param  data [IN] 读取的数据存储的位置
 * @param  dataLen [IN] data 的大小，缓冲区大小应该大于18K字节。此最小缓冲区大小是根据底层 ssl 库规格要求定义的。
 * @param  readLen [OUT] 已读取长度
 * @retval SCF_SUCCESS 成功
 * @retval SCF_SSL_ERR_WANT_READ为合理错误场景,可以继续读取
 * @retval 其它错误码为异常
 */
int32_t SCF_Read(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen);

/**
 * @ingroup scf
 * @brief  写安全传输数据
 * @param  ctx [IN] 安全策略上下文
 * @param  data [IN] 写入的数据
 * @param  dataLen [IN] data 的大小。默认单次最大写入长度是16K字节
 * @param  writeLen [OUT] 已写入长度
 * @retval SCF_SUCCESS 成功
 * @retval SCF_SSL_ERR_WANT_WRITE为合理错误场景,可以继续写入
 * @retval 其它错误码为异常
 */
int32_t SCF_Write(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen);

// obj 配置必要
/**
 * @ingroup scf
 * @brief  配置安全通信的使用的 socket
 * @param  obj [IN] 安全策略对象实例
 * @param  fd [IN] socket id
 * @return 错误码，成功则返回 SCF_SUCCESS
 */
int32_t SCF_SetFd(SCF_PolicyObj *obj, int32_t fd);

/**
 * @ingroup scf
 * @brief  配置安全通信的协议版本号
 * @param  ctx [IN] 安全策略上下文
 * @param  minVersion [IN] 最低版本
 * @param  maxVersion [IN] 最高版本
 * @param  forbidVersion [IN] 禁用版本数组
 * @param  forbidVersionLen [IN] forbidVersion 的长度
 * @return 错误码，成功则返回 SCF_SUCCESS
 * @attention 未指定时，scf 根据安全策略选择满足安全规范要求的版本。当前仅支持 TLS 1.3，后续放开 TLS 1.2
 */
int32_t SCF_SetProtocolVersion(
    SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion, uint32_t *forbidVersion, uint32_t forbidVersionLen);

// obj 查询
/**
 * @ingroup scf
 * @brief  获取当前协商的协议版本号
 * @param  obj [IN] 安全策略对象实例
 * @return 当前协议版本号，返回的是字符串常量，无需释放返回值
 * @attention 仅在协商建链成功后，可以获取到版本号
 */
const char *SCF_GetProtocolVersion(SCF_PolicyObj *obj);

/**
 * @ingroup scf
 * @brief  获取建链时使用的证书,使用前需要先建链。
 * @param  obj [IN] 安全策略对象实例
 * @return 指向本地证书的指针
 */
void *SCF_GetCurrentCert(SCF_PolicyObj *obj);
}

#ifdef __cplusplus
}
#endif

#endif
