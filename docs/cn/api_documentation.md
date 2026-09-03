# API 文档

## 目录

- [1 数据结构](#1-数据结构)
    - [1.1 枚举](#11-枚举)
        - [1.1.1 初始化类型](#111-初始化类型)
        - [1.1.2 协议版本号](#112-协议版本号)
        - [1.1.3 文件存储类型](#113-文件存储类型)
        - [1.1.4 通信角色](#114-通信角色)
        - [1.1.5 校验模式](#115-校验模式)
        - [1.1.6 安全策略等级](#116-安全策略等级)
        - [1.1.7 证书格式类型](#117-证书格式类型)
        - [1.1.8 证书用途](#118-证书用途)
        - [1.1.9 通信算法套](#119-通信算法套)
        - [1.1.10 日志级别](#1110-日志级别)
        - [1.1.11 协议版本号_配置文件](#1111-协议版本号_配置文件)
        - [1.1.12 协议算法套_配置文件](#1112-协议算法套_配置文件)
        - [1.1.13 证书用途_配置文件](#1113-证书用途_配置文件)
        - [1.1.14 协议版本号_字符串](#1114-协议版本号_字符串)
        - [1.1.15 RBAC 角色](#1115-rbac-角色)
        - [1.1.16 RBAC 角色来源](#1116-rbac-角色来源)
        - [1.1.17 RBAC 资源操作](#1117-rbac-资源操作)
        - [1.1.18 RBAC 资源类型](#1118-rbac-资源类型)
        - [1.1.19 RBAC 策略效果](#1119-rbac-策略效果)
        - [1.1.20 连接安全强度](#1120-连接安全强度)
        - [1.1.21 证书校验策略](#1121-证书校验策略)
        - [1.1.22 连接状态](#1122-连接状态)
        - [1.1.23 对称加密算法](#1123-对称加密算法)
        - [1.1.24 非对称算法](#1124-非对称算法)
        - [1.1.25 哈希算法](#1125-哈希算法)
        - [1.1.26 密钥交换算法](#1126-密钥交换算法)
        - [1.1.27 传输操作结果](#1127-传输操作结果)
        - [1.1.28 传输地址类型](#1128-传输地址类型)
        - [1.1.29 传输协议类型](#1129-传输协议类型)
        - [1.1.30 PSK 哈希算法标识](#1130-psk-哈希算法标识)
        - [1.1.31 安全强度常量](#1131-安全强度常量)
        - [1.1.32 TLS 命名组常量](#1132-tls-命名组常量)
    - [1.2 结构体](#12-结构体)
        - [1.2.1 文件上下文](#121-文件上下文)
        - [1.2.2 安全策略上下文](#122-安全策略上下文)
        - [1.2.3 安全策略对象](#123-安全策略对象)
        - [1.2.4 安全会话对象](#124-安全会话对象)
        - [1.2.5 RBAC 策略规则](#125-rbac-策略规则)
        - [1.2.6 安全连接配置](#126-安全连接配置)
        - [1.2.7 密码引擎能力](#127-密码引擎能力)
        - [1.2.8 密码引擎配置](#128-密码引擎配置)
        - [1.2.9 密钥句柄](#129-密钥句柄)
        - [1.2.10 传输端点地址](#1210-传输端点地址)
        - [1.2.11 传输配置](#1211-传输配置)
    - [1.3 回调函数定义](#13-回调函数定义)
        - [1.3.1 ExternalLogFunction](#131-ExternalLogFunction)
        - [1.3.2 ExternalDecryptFunction](#132-ExternalDecryptFunction)
        - [1.3.3 SCF_AppVerifyFunc](#133-SCF_AppVerifyFunc)
        - [1.3.4 SCF_PskUseSessionCb](#134-SCF_PskUseSessionCb)
        - [1.3.5 SCF_PskFindSessionCb](#135-SCF_PskFindSessionCb)
    - [1.4 错误码](#14-错误码)
    - [1.5 配置文件](#15-配置文件)
        - [1.5.1 安全通信配置文件](#151-安全通信配置文件)
- [2 API接口](#2-API接口)
    - [2.1 安全策略模块](#21-安全策略模块)
        - [2.1.1 SetExternalLogFunction](#211-SetExternalLogFunction)
        - [2.1.2 GetErrorMessage](#212-GetErrorMessage)
        - [2.1.3 SetExternalDecryptFunction](#213-SetExternalDecryptFunction)
        - [2.1.4 SCF_Init](#214-SCF_Init)
        - [2.1.5 SCF_DeInit](#215-SCF_DeInit)
        - [2.1.6 SCF_CreatePolicyCtx](#216-SCF_CreatePolicyCtx)
        - [2.1.7 SCF_FreePolicyCtx](#217-SCF_FreePolicyCtx)
        - [2.1.8 SCF_SetPolicy](#218-SCF_SetPolicy)
        - [2.1.9 SCF_GetPolicy](#219-SCF_GetPolicy)
        - [2.1.10 SCF_SetConfigFile](#2110-SCF_SetConfigFile)
        - [2.1.11 SCF_CreatePolicyObj](#2111-SCF_CreatePolicyObj)
        - [2.1.12 SCF_FreePolicyObj](#2112-SCF_FreePolicyObj)
        - [2.1.13 SCF_SetCipherSuites](#2113-SCF_SetCipherSuites)
        - [2.1.14 SCF_GetCipherSuites](#2114-SCF_GetCipherSuites)
        - [2.1.15 SCF_SetAppVerifyCallback](#2115-SCF_SetAppVerifyCallback)
        - [2.1.16 SCF_SetProtocolVersion](#2116-SCF_SetProtocolVersion)
        - [2.1.17 SCF_GetProtocolVersion](#2117-SCF_GetProtocolVersion)
        - [2.1.18 SCF_FreeBuffer](#2118-SCF_FreeBuffer)
    - [2.2 安全凭据证书](#22-安全凭据证书)
        - [2.2.1 SCF_FileCtxNew](#221-SCF_FileCtxNew)
        - [2.2.2 SCF_FileCtxFree](#222-SCF_FileCtxFree)
        - [2.2.3 SCF_FileCtxSetBuf](#223-SCF_FileCtxSetBuf)
        - [2.2.4 SCF_FileCtxSetPwd](#224-SCF_FileCtxSetPwd)
        - [2.2.5 SCF_AddCert](#225-SCF_AddCert)
        - [2.2.6 SCF_SetKey](#226-SCF_SetKey)
        - [2.2.7 SCF_CheckPrivateKey](#227-SCF_CheckPrivateKey)
        - [2.2.8 SCF_GetCurrentCert](#228-SCF_GetCurrentCert)
        - [2.2.9 SCF_GetPeerCert](#229-SCF_GetPeerCert)
        - [2.2.10 SCF_FreeCert](#2210-SCF_FreeCert)
        - [2.2.11 SCF_GetCertVersion](#2211-SCF_GetCertVersion)
        - [2.2.12 SCF_GetCertStartTime](#2212-SCF_GetCertStartTime)
        - [2.2.13 SCF_GetCertEndTime](#2213-SCF_GetCertEndTime)
        - [2.2.14 SCF_GetCertSerialNumber](#2214-SCF_GetCertSerialNumber)
    - [2.3 安全凭据PSK](#23-安全凭据PSK)
        - [2.3.1 SCF_SetPskFindSessionCallback](#231-SCF_SetPskFindSessionCallback)
        - [2.3.2 SCF_SetPskUseSessionCallback](#232-SCF_SetPskUseSessionCallback)
        - [2.3.3 SCF_SessionNew](#233-SCF_SessionNew)
        - [2.3.4 SCF_SessionFree](#234-SCF_SessionFree)
        - [2.3.5 SCF_SessionSetMasterKey](#235-SCF_SessionSetMasterKey)
        - [2.3.6 SCF_SessionSetCipher](#236-SCF_SessionSetCipher)
        - [2.3.7 SCF_SessionGetCipher](#237-SCF_SessionGetCipher)
        - [2.3.8 SCF_SessionFreeCipher](#238-SCF_SessionFreeCipher)
        - [2.3.9 SCF_SessionSetProtocolVersion](#239-SCF_SessionSetProtocolVersion)
        - [2.3.10 SCF_SessionGetProtocolVersion](#2310-SCF_SessionGetProtocolVersion)
        - [2.3.11 SCF_CipherFind](#2311-SCF_CipherFind)
        - [2.3.12 SCF_SetUserData](#2312-SCF_SetUserData)
        - [2.3.13 SCF_GetUserData](#2313-SCF_GetUserData)
    - [2.4 安全密钥更新](#24-安全密钥更新)
        - [2.4.1 SCF_SetKeyAutoUpdateParam](#241-SCF_SetKeyAutoUpdateParam)
        - [2.4.2 SCF_GetKeyAutoUpdateParam](#242-SCF_GetKeyAutoUpdateParam)
        - [2.4.3 SCF_ObjKeyUpdate](#243-SCF_ObjKeyUpdate)
        - [2.4.4 SCF_GetKeyUpdateInfo](#244-SCF_GetKeyUpdateInfo)
    - [2.5 安全通信模块](#25-安全通信模块)
        - [2.5.1 SCF_SetFd](#251-SCF_SetFd)
        - [2.5.2 SCF_Connect](#252-SCF_Connect)
        - [2.5.3 SCF_Accept](#253-SCF_Accept)
        - [2.5.4 SCF_Close](#254-SCF_Close)
        - [2.5.5 SCF_Read](#255-SCF_Read)
        - [2.5.6 SCF_Write](#256-SCF_Write)
    - [2.6 RBAC 节点身份与角色](#26-rbac-节点身份与角色)
        - [2.6.1 SCF_GetCertNodeId](#261-SCF_GetCertNodeId)
        - [2.6.2 SCF_GetCertRbacRole](#262-SCF_GetCertRbacRole)
        - [2.6.3 SCF_SetNodeRoleMapping](#263-SCF_SetNodeRoleMapping)
        - [2.6.4 SCF_RemoveNodeRoleMapping](#264-SCF_RemoveNodeRoleMapping)
        - [2.6.5 SCF_GetNodeRbacRole](#265-SCF_GetNodeRbacRole)
    - [2.7 RBAC 管理与策略规则](#27-rbac-管理与策略规则)
        - [2.7.1 SCF_EnableRbac](#271-SCF_EnableRbac)
        - [2.7.2 SCF_ListMasterNodes](#272-SCF_ListMasterNodes)
        - [2.7.3 SCF_IsMasterNode](#273-SCF_IsMasterNode)
        - [2.7.4 SCF_AddPolicyRule](#274-SCF_AddPolicyRule)
        - [2.7.5 SCF_RemovePolicyRule](#275-SCF_RemovePolicyRule)
        - [2.7.6 SCF_ListPolicyRules](#276-SCF_ListPolicyRules)
    - [2.8 RBAC 资源权限校验](#28-rbac-资源权限校验)
        - [2.8.1 SCF_CheckResourcePermission](#281-SCF_CheckResourcePermission)
    - [2.9 安全连接接口](#29-安全连接接口)
        - [2.9.1 SCFConnection](#291-SCFConnection)
        - [2.9.2 安全连接便捷函数](#292-安全连接便捷函数)
        - [2.9.3 传输与密码引擎注册](#293-传输与密码引擎注册)
    - [2.10 密码引擎接口](#210-密码引擎接口)
        - [2.10.1 ICryptoEngine](#2101-ICryptoEngine)
        - [2.10.2 DefaultSoftwareCryptoEngine](#2102-DefaultSoftwareCryptoEngine)
        - [2.10.3 密码引擎工厂](#2103-密码引擎工厂)
    - [2.11 传输接口](#211-传输接口)
        - [2.11.1 TransportAddress 工厂方法](#2111-TransportAddress-工厂方法)
        - [2.11.2 ITransport](#2112-ITransport)
        - [2.11.3 ITransportFactory](#2113-ITransportFactory)

## 1 数据结构

### 1.1 枚举

#### 1.1.1 初始化类型

##### 定义

```c++
#define SCF_INIT_FLAG_OPENSSL 1
```

##### 用途

在调用[SCF_Init](#214-SCF_Init)时指定初始化的底层 TLS 实现。

##### 属性说明

| 名称                      | 值 | 含义                  |
|-------------------------|---|---------------------|
| SCF_INIT_FLAG_OPENSSL | 1 | 使用 OpenSSL 初始化SCF |

#### 1.1.2 协议版本号

##### 定义

```c++
#define SCF_SSL_VERSION_TLS12 0x0303u
#define SCF_SSL_VERSION_TLS13 0x0304u
```

##### 用途

在调用[SCF_SetProtocolVersion](#2116-SCF_SetProtocolVersion)时设置协议版本号

##### 属性说明

| 名称                      | 值       | 含义       |
|-------------------------|---------|----------|
| SCF_SSL_VERSION_TLS12 | 0x0303u | TLS1.2版本 |
| SCF_SSL_VERSION_TLS13 | 0x0304u | TLS1.3版本 |

#### 1.1.3 文件存储类型

##### 定义

```c++
typedef enum SCFStoreType {
    SCF_STORE_FILE_PATH = 0,  // 存储在文件系统上，传入的是文件路径。业务应该传入的是绝对路径
    SCF_STORE_BUFFER,         // 存储在内存中，传入的是文件 buffer
    SCF_STORE_ERROR,          // 不支持的类型
} SCF_STORE_TYPE;
```

##### 用途

在调用[SCF_FileCtxSetBuf](#223-SCF_FileCtxSetBuf)时给[SCF_FILE_CTX](#121-文件上下文)配置存储属性时，根据实际存储场景指定Type类型

##### 属性说明

| 名称                    | 值 | 含义                         |
|-----------------------|---|----------------------------|
| SCF_STORE_FILE_PATH | 0 | 存储在文件系统上，传入的是文件路径。**绝对路径** |
| SCF_STORE_BUFFER    | 1 | 存储在内存中，传入的是文件 buffer       |
| SCF_STORE_ERROR     | 2 | 不支持的类型                     |

#### 1.1.4 通信角色

##### 定义

```c++
typedef enum SCFRole {
    SCF_ROLE_NONE = 0,    // 未指定
    SCF_ROLE_CLIENT = 1,  // 客户端
    SCF_ROLE_SERVER = 2,  // 服务端
} SCF_ROLE;
```

##### 用途

在调用[SCF_SetPolicy](#218-SCF_SetPolicy)时指定初始化的通信角色

##### 属性说明

| 名称                | 值 | 含义  |
|-------------------|---|-----|
| SCF_ROLE_NONE   | 0 | 未指定 |
| SCF_ROLE_CLIENT | 1 | 客户端 |
| SCF_ROLE_SERVER | 2 | 服务端 |

#### 1.1.5 校验模式

##### 定义

```c++
typedef enum SCFVerifyMode {
    SCF_VERIFY_MODE_NONE = 0,  // 不校验对端
    SCF_VERIFY_DEFAULT = 1,  // 默认校验方式。使用证书时相当于 VERIFY_PEER 和 VERIFY_FAIL_IF_NO_PEER_CERT 同时生效
    SCF_VERIFY_CUSTOMER = 2,  // 使用用户注册的校验实现，由用户检查。
    SCF_VERIFY_PEER = 4,      // 校验对端
    SCF_VERIFY_FAIL_IF_NO_PEER_CERT = 8,  // 对端无证书则校验失败。应该要和 peer 一起使用
} SCF_VERIFY_MODE;
```

##### 用途

在调用[SCF_SetPolicy](#218-SCF_SetPolicy)时指定校验模式

##### 属性说明

| 名称                                | 值 | 含义                                                                                            |
|-----------------------------------|---|-----------------------------------------------------------------------------------------------|
| SCF_VERIFY_MODE_NONE            | 0 | 不校验对端                                                                                         |
| SCF_VERIFY_DEFAULT              | 1 | 默认校验方式。<br/>使用证书时相当于 <code>VERIFY_PEER</code> 和 <code>VERIFY_FAIL_IF_NO_PEER_CERT</code> 同时生效 |
| SCF_VERIFY_CUSTOMER             | 2 | 使用用户注册的校验实现，由用户检查。要和 peer 一起使用                                                                |
| SCF_VERIFY_PEER                 | 4 | 校验对端                                                                                          |
| SCF_VERIFY_FAIL_IF_NO_PEER_CERT | 8 | 对端无证书则校验失败。要和 peer 一起使用                                                                       |

#### 1.1.6 安全策略等级

##### 定义

```c++
typedef enum SCFPolicyMode {
    SCF_POLICY_HIGH = 0,    // 高安全，低兼容模式。随安全规范演进。
    SCF_POLICY_MIDDLE = 1,  // 中安全，较高兼容模式。随安全规范演进。
    SCF_POLICY_CUSTOMER = 2, // CUSTOMER 表示客户化定制。当且仅当业务是出于存量场景兼容性配置，允许业务指定放宽特定校验，自行保证安全性。
} SCF_POLICY_MODE;
```

##### 用途

在调用[SCF_SetPolicy](#218-SCF_SetPolicy)时指定安全校验策略模式

##### 属性说明

| 名称                    | 值 | 含义                                                        |
|-----------------------|---|-----------------------------------------------------------|
| SCF_POLICY_HIGH     | 0 | 高安全，低兼容模式。随安全规范演进。                                        |
| SCF_POLICY_MIDDLE   | 1 | 中安全，较高兼容模式。随安全规范演进。                                       |
| SCF_POLICY_CUSTOMER | 2 | CUSTOMER 表示客户化定制。当且仅当业务是出于存量场景兼容性配置，允许业务指定放宽特定校验，自行保证安全性。 |

#### 1.1.7 证书格式类型

##### 定义

```c++
typedef enum SCFStoreFormat {
    SCF_STORE_FORMAT_PEM = 0  // 存储数据是 PEM 格式的
} SCF_STORE_FORMAT;
```

##### 用途

在调用[SCF_FileCtxSetBuf](#223-SCF_FileCtxSetBuf)时给[SCF_FILE_CTX](#121-文件上下文)配置证书格式

##### 属性说明

| 名称                     | 值 | 含义            |
|------------------------|---|---------------|
| SCF_STORE_FORMAT_PEM | 0 | 存储数据是 PEM 格式的 |

#### 1.1.8 证书用途

##### 定义

```c++
typedef enum SCFCertType {
    SCF_CERT_TYPE_CA = 0,        // CA 证书
    SCF_CERT_TYPE_EE = 1,        // 设备证书
    SCF_CERT_TYPE_CRL = 2,       // CRL
    SCF_CERT_TYPE_EE_CHAIN = 3,  // 第一本设备证书，最后一本根证书，多本证书构成的证书链
} SCF_CERT_TYPE;
```

##### 用途

在调用[SCF_AddCert](#225-SCF_AddCert)时指定添加的证书的用途

##### 属性说明

| 名称                       | 值 | 含义                         |
|--------------------------|---|----------------------------|
| SCF_CERT_TYPE_CA       | 0 | CA 证书                      |
| SCF_CERT_TYPE_EE       | 1 | 终端实体证书，即设备证书               |
| SCF_CERT_TYPE_CRL      | 2 | CRL                        |
| SCF_CERT_TYPE_EE_CHAIN | 3 | 第一本设备证书，最后一本根证书，多本证书构成的证书链 |

#### 1.1.9 通信算法套

##### 定义

```c++
typedef enum {
    /* TLS1.2 cipher suite */
    SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,        // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,        // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,          // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,          // 取值来源于 rfc 5289
    SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,    // 取值来源于 rfc 7905
    SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,  // 取值来源于 rfc 7905
    /* TLS1.3 cipher suite. 没有 SCF_SSL_AES_128_CCM_8_SHA256，因为不在公司规范白名单 */
    SCF_SSL_AES_128_GCM_SHA256 = 0x1301,        // 取值来源于 rfc 8446
    SCF_SSL_AES_256_GCM_SHA384 = 0x1302,        // 取值来源于 rfc 8446
    SCF_SSL_CHACHA20_POLY1305_SHA256 = 0x1303,  // 取值来源于 rfc 8446
    SCF_SSL_AES_128_CCM_SHA256 = 0x1304,        // 取值来源于 rfc 8446
} SCF_SSL_CipherSuite;
```

##### 用途

在调用[SCF_SetCipherSuites](#2113-SCF_SetCipherSuites)或[SCF_SessionSetCipher](#236-SCF_SessionSetCipher)时指定算法套。

##### 属性说明

| 名称                                                  | 值      | 含义                        |
|-----------------------------------------------------|--------|---------------------------|
| SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | 0xC02B | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | 0xC02C | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | 0xC02F | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | 0xC030 | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | 0xCCA8 | 取值来源 RFC 7905，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | 0xCCA9 | 取值来源 RFC 7905，仅支持 TLS 1.2 |
| SCF_SSL_AES_128_GCM_SHA256                        | 0x1301 | 取值来源rfc8446，仅支持TLS1.3协议使用 |
| SCF_SSL_AES_256_GCM_SHA384                        | 0x1302 | 取值来源rfc8446，仅支持TLS1.3协议使用 |
| SCF_SSL_CHACHA20_POLY1305_SHA256                  | 0x1303 | 取值来源rfc8446，仅支持TLS1.3协议使用 |
| SCF_SSL_AES_128_CCM_SHA256                        | 0x1304 | 取值来源rfc8446，仅支持TLS1.3协议使用 |

#### 1.1.10 日志级别

##### 定义

```c++
typedef enum LogLevel {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,   // log level debug
    LOG_LEVEL_INFO = 2,    // log level info
    LOG_LEVEL_WARN = 3,    // log level warn
    LOG_LEVEL_ERROR = 4,   // log level error
    LOG_LEVEL_CRITICAL = 5 // log level critical
} LOG_LEVEL;
```

##### 用途

日志回调函数[ExternalLogFunction](#131-ExternalLogFunction)中的日志级别，集成时需要按照不同日志级别进行处理

##### 属性说明

| 名称                 | 值 | 含义           |
|--------------------|---|--------------|
| LOG_LEVEL_TRACE    | 0 | trace级别日志    |
| LOG_LEVEL_DEBUG    | 1 | debug级别日志    |
| LOG_LEVEL_INFO     | 2 | info级别日志     |
| LOG_LEVEL_WARN     | 3 | warn级别日志     |
| LOG_LEVEL_ERROR    | 4 | error级别日志    |
| LOG_LEVEL_CRITICAL | 5 | critical级别日志 |

#### 1.1.11 协议版本号_配置文件

##### 定义

```c++
std::unordered_map<std::string, uint32_t> tlsVersionMap = {
    {"SSL_VERSION_TLS12", SCF_SSL_VERSION_TLS12},
    {"SSL_VERSION_TLS13", SCF_SSL_VERSION_TLS13},
};
```

##### 用途

在安全通信配置文件的 `tlsVersion.minVersion`、`tlsVersion.maxVersion` 和 `tlsVersion.forbidVersion` 字段中指定协议版本。

##### 属性说明

| 名称                | 值       | 含义     |
|-------------------|---------|--------|
| SSL_VERSION_TLS12 | 0x0303u | TLS1.2 |
| SSL_VERSION_TLS13 | 0x0304u | TLS1.3 |

#### 1.1.12 协议算法套_配置文件

##### 定义

```c++
inline std::unordered_map<std::string, SCF_SSL_CipherSuite> cipherMap = {
    /* TLS1.2 cipher suite */
    {"SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
    {"SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
    {"SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256", SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
    {"SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384", SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
    {"SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
    {"SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
    /* TLS1.3 cipher suite. 没有 SCF_SSL_AES_128_CCM_8_SHA256，因为不在公司规范白名单 */
    {"SCF_SSL_AES_128_GCM_SHA256", SCF_SSL_AES_128_GCM_SHA256},
    {"SCF_SSL_AES_256_GCM_SHA384", SCF_SSL_AES_256_GCM_SHA384},
    {"SCF_SSL_CHACHA20_POLY1305_SHA256", SCF_SSL_CHACHA20_POLY1305_SHA256},
    {"SCF_SSL_AES_128_CCM_SHA256", SCF_SSL_AES_128_CCM_SHA256},
};
```

##### 用途

在安全通信配置文件的 `tlsCipherSuites` 数组中指定算法套。

##### 属性说明

| 名称                                                  | 值      | 含义                        |
|-----------------------------------------------------|--------|---------------------------|
| SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | 0xC02B | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | 0xC02C | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | 0xC02F | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | 0xC030 | 取值来源 RFC 5289，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | 0xCCA8 | 取值来源 RFC 7905，仅支持 TLS 1.2 |
| SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | 0xCCA9 | 取值来源 RFC 7905，仅支持 TLS 1.2 |
| SCF_SSL_AES_128_GCM_SHA256                        | 0x1301 | 取值来源rfc8446，仅支持TLS1.3协议使用 |
| SCF_SSL_AES_256_GCM_SHA384                        | 0x1302 | 取值来源rfc8446，仅支持TLS1.3协议使用 |
| SCF_SSL_CHACHA20_POLY1305_SHA256                  | 0x1303 | 取值来源rfc8446，仅支持TLS1.3协议使用 |
| SCF_SSL_AES_128_CCM_SHA256                        | 0x1304 | 取值来源rfc8446，仅支持TLS1.3协议使用 |

#### 1.1.13 证书用途_配置文件

##### 定义

```c++
std::unordered_map<std::string, SCF_CERT_TYPE> tlsCertTypeMap = {
    {"CA", SCF_CERT_TYPE_CA},
    {"EE", SCF_CERT_TYPE_EE},
    {"CRL", SCF_CERT_TYPE_CRL},
    {"EE_CHAIN", SCF_CERT_TYPE_EE_CHAIN},
};
```

##### 用途

在安全通信配置文件的 `certs[].cert.certType` 字段中指定证书用途。

##### 属性说明

| 名称       | 值 | 含义                         |
|----------|---|----------------------------|
| CA       | 0 | CA 证书                      |
| EE       | 1 | 设备证书                       |
| CRL      | 2 | CRL                        |
| EE_CHAIN | 3 | 第一本设备证书，最后一本根证书，多本证书构成的证书链 |

#### 1.1.14 协议版本号_字符串

##### 定义

```c++
#define SCF_SSL_VERSION_TLS12_STR "TLSv1.2"
#define SCF_SSL_VERSION_TLS13_STR "TLSv1.3"
```

##### 用途

在调用[SCF_GetProtocolVersion](#2117-SCF_GetProtocolVersion)时返回协议版本号

##### 属性说明

| 名称                          | 值       | 含义       |
|-----------------------------|---------|----------|
| SCF_SSL_VERSION_TLS12_STR | TLSv1.2 | TLS1.2版本 |
| SCF_SSL_VERSION_TLS13_STR | TLSv1.3 | TLS1.3版本 |

#### 1.1.15 RBAC 角色

##### 定义

```c++
typedef enum SCFRbacRole {
    SCF_RBAC_ROLE_UNKNOWN = 0,
    SCF_RBAC_ROLE_MASTER = 1,
    SCF_RBAC_ROLE_SLAVE = 2,
} SCF_RBAC_ROLE;
```

##### 用途

表示节点的 RBAC 角色。

##### 属性说明

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_RBAC_ROLE_UNKNOWN | 0 | 未识别或未配置角色，不能用于新增或更新映射 |
| SCF_RBAC_ROLE_MASTER | 1 | 主节点角色 |
| SCF_RBAC_ROLE_SLAVE | 2 | 从节点角色 |

#### 1.1.16 RBAC 角色来源

##### 定义

```c++
typedef enum SCFRbacRoleSource {
    SCF_RBAC_ROLE_SRC_NONE = 0,
    SCF_RBAC_ROLE_SRC_CERT = 1,
    SCF_RBAC_ROLE_SRC_MAPPING = 2,
} SCF_RBAC_ROLE_SOURCE;
```

##### 用途

表示 RBAC 角色的解析来源。

##### 属性说明

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_RBAC_ROLE_SRC_NONE | 0 | 未获取到角色 |
| SCF_RBAC_ROLE_SRC_CERT | 1 | 角色来自证书扩展 |
| SCF_RBAC_ROLE_SRC_MAPPING | 2 | 角色来自节点角色映射 |

#### 1.1.17 RBAC 资源操作

##### 定义

```c++
typedef enum SCFResourceAction {
    SCF_RES_ACTION_UNKNOWN = 0,
    SCF_RES_ACTION_APPLY = 1,
    SCF_RES_ACTION_RELEASE = 2,
} SCF_RESOURCE_ACTION;
```

##### 用途

表示 RBAC 策略规则约束的资源操作。`SCF_RES_ACTION_APPLY` 和 `SCF_RES_ACTION_RELEASE` 可按位组合。

##### 属性说明

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_RES_ACTION_UNKNOWN | 0 | 未知操作，不能用于新增策略规则 |
| SCF_RES_ACTION_APPLY | 1 | 申请资源 |
| SCF_RES_ACTION_RELEASE | 2 | 释放资源 |

#### 1.1.18 RBAC 资源类型

##### 定义

```c++
typedef enum SCFResourceType {
    SCF_RES_TYPE_NONE = 0,
    SCF_RES_TYPE_FD = 1,
    SCF_RES_TYPE_NUMA = 2,
    SCF_RES_TYPE_ADDR = 4,
    SCF_RES_TYPE_ALL = 7,
} SCF_RESOURCE_TYPE;
```

##### 用途

表示 RBAC 策略规则约束的资源类型。除 `SCF_RES_TYPE_NONE` 外，各资源类型可按位组合。

##### 属性说明

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_RES_TYPE_NONE | 0 | 无资源类型，不能用于新增策略规则 |
| SCF_RES_TYPE_FD | 1 | 文件描述符资源 |
| SCF_RES_TYPE_NUMA | 2 | NUMA 资源 |
| SCF_RES_TYPE_ADDR | 4 | 地址空间资源 |
| SCF_RES_TYPE_ALL | 7 | 所有支持的资源类型 |

#### 1.1.19 RBAC 策略效果

##### 定义

```c++
typedef enum SCFPolicyEffect {
    SCF_POLICY_EFFECT_ALLOW = 0,
    SCF_POLICY_EFFECT_DENY = 1,
} SCF_POLICY_EFFECT;
```

##### 用途

表示 RBAC 策略规则允许或拒绝匹配的资源操作。

##### 属性说明

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_POLICY_EFFECT_ALLOW | 0 | 允许访问 |
| SCF_POLICY_EFFECT_DENY | 1 | 拒绝访问 |

#### 1.1.20 连接安全强度

`SCFSecurityLevel`（别名 `SCF_SECURITY_LEVEL`）用于配置 `SCFConnection` 的 TLS 版本、算法套和密钥交换组
优先级。等级名称不保证最终协商结果达到对应的最低安全强度：部分等级允许较低强度算法或经典密钥交换组回退，
密钥交换组配置失败时还会继续使用 OpenSSL 默认组。实际安全属性以握手协商结果为准；带 `_PQ` 后缀的优先项
需要加载抗量子 Provider。

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_SECURITY_112BIT | 0 | 配置标签为 112-bit；TLS 1.2～1.3、AES-128/256-GCM、X25519/P-256 |
| SCF_SECURITY_128BIT | 1 | 配置标签为 128-bit；TLS 1.3、AES-128/256-GCM、ChaCha20-Poly1305、X25519/P-256；默认值 |
| SCF_SECURITY_192BIT | 2 | 优先 AES-256-GCM 和 P-384，同时允许 AES-128-GCM、X25519 回退 |
| SCF_SECURITY_256BIT | 3 | 优先 AES-256-GCM 和 P-521，同时允许 AES-128-GCM、P-384、X25519 回退 |
| SCF_SECURITY_128BIT_PQ | 4 | 优先 Hybrid Kyber 密钥交换组，同时允许经典 X25519/P-256 回退 |
| SCF_SECURITY_256BIT_PQ | 5 | 优先 Hybrid Kyber/ML-KEM 密钥交换组，同时允许经典 P-521/P-384 回退 |

#### 1.1.21 证书校验策略

`SCFCertVerifyPolicy`（别名 `SCF_CERT_VERIFY_POLICY`）指定 `SCFConnection` 对对端证书的校验策略。

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_CERT_VERIFY_NONE | 0 | 不校验对端证书；可用于 PSK，证书模式下使用会失去对端身份认证能力并面临中间人攻击风险 |
| SCF_CERT_VERIFY_OPTIONAL | 1 | 当前实现映射为 `SCF_VERIFY_DEFAULT`，实际仍要求并校验对端证书 |
| SCF_CERT_VERIFY_REQUIRED | 2 | 对端必须提供有效证书；默认值 |
| SCF_CERT_VERIFY_STRICT | 3 | 当前实现与 `SCF_CERT_VERIFY_REQUIRED` 使用相同校验模式 |

CRL 是否加载由 `SCFConnectionConfig::crlPath` 独立控制；当前高层连接实现未配置 OCSP。因此，
`SCF_CERT_VERIFY_OPTIONAL` 和 `SCF_CERT_VERIFY_STRICT` 暂未实现名称所表达的差异化行为。

#### 1.1.22 连接状态

`SCFConnectionState` 的别名为 `SCF_CONNECTION_STATE`。

| `SCF_CONNECTION_STATE` 名称 | 值 | 含义 |
|---|---|---|
| SCF_CONN_INIT | 0 | 初始状态 |
| SCF_CONN_CONNECTING | 1 | 正在连接或进行 TLS 握手 |
| SCF_CONN_CONNECTED | 2 | 安全通道已就绪 |
| SCF_CONN_CLOSING | 3 | 正在关闭 |
| SCF_CONN_CLOSED | 4 | 已关闭 |
| SCF_CONN_ERROR | 5 | 错误状态 |

#### 1.1.23 对称加密算法

| `scf::SymmetricAlgorithm` 名称 | 值 | 含义 |
|---|---|---|
| AES_128_GCM | 1 | AES-128-GCM |
| AES_256_GCM | 2 | AES-256-GCM |
| AES_128_CCM | 3 | AES-128-CCM |
| CHACHA20_POLY1305 | 4 | ChaCha20-Poly1305 |
| SM4_GCM | 5 | SM4-GCM |
| CUSTOM | 99 | 自定义对称算法 |

#### 1.1.24 非对称算法

| `scf::AsymmetricAlgorithm` 名称 | 值 | 含义 |
|---|---|---|
| RSA | 1 | RSA |
| ECDSA_P256 | 2 | ECDSA P-256 |
| ECDSA_P384 | 3 | ECDSA P-384 |
| ECDSA_P521 | 4 | ECDSA P-521 |
| EDDSA_25519 | 5 | EdDSA 25519 |
| SM2 | 6 | 国密 SM2 |
| CUSTOM | 99 | 自定义非对称算法 |

#### 1.1.25 哈希算法

| `scf::HashAlgorithm` 名称 | 值 | 含义 |
|---|---|---|
| SHA256 | 1 | SHA-256 |
| SHA384 | 2 | SHA-384 |
| SHA512 | 3 | SHA-512 |
| SM3 | 4 | 国密 SM3 |
| CUSTOM | 99 | 自定义哈希算法 |

#### 1.1.26 密钥交换算法

| `scf::KeyExchangeAlgorithm` 名称 | 值 | 含义 |
|---|---|---|
| ECDHE | 1 | ECDHE 密钥交换 |
| DHE | 2 | DHE 密钥交换 |
| PSK | 3 | PSK 密钥交换 |
| SM2_KEY_EXCHANGE | 4 | 国密 SM2 密钥交换 |
| CUSTOM | 99 | 自定义密钥交换算法 |

#### 1.1.27 传输操作结果

| `scf::TransportResult` 名称 | 值 | 含义 |
|---|---|---|
| SUCCESS | 0 | 操作成功 |
| ERROR | -1 | 操作失败 |
| WOULD_BLOCK | -2 | 非阻塞操作暂时无法完成，需要重试 |
| CONNECTION_CLOSED | -3 | 连接已关闭 |
| TIMEOUT | -4 | 操作超时 |

#### 1.1.28 传输地址类型

| `scf::TransportAddressType` 名称 | 值 | 含义 |
|---|---|---|
| IPv4 | 0 | IPv4 地址 |
| IPv6 | 1 | IPv6 地址 |
| DOMAIN | 2 | 域名 |
| URMA | 3 | URMA 地址 |
| CUSTOM | 99 | 自定义地址格式 |

#### 1.1.29 传输协议类型

| `scf::TransportProtocol` 名称 | 值 | 含义 |
|---|---|---|
| TCP | 0 | TCP 协议 |
| UDP | 1 | UDP 协议 |
| URMA | 2 | URMA 协议 |
| CUSTOM | 99 | 自定义传输协议 |

#### 1.1.30 PSK 哈希算法标识

以下常量用于 `SCF_PskUseSessionCb` 的 `hashAlgo` 参数，表示 TLS 算法套使用的哈希算法。
客户端在 ClientHello 阶段尚未确定算法套时，`hashAlgo` 为 `SCF_CRYPT_MD_UNKNOWN`。

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_CRYPT_MD_UNKNOWN | 0 | 哈希算法尚未确定 |
| SCF_CRYPT_MD_SHA256 | 10006 | SHA-256 |
| SCF_CRYPT_MD_SHA384 | 10007 | SHA-384 |

#### 1.1.31 安全强度常量

以下常量表示 NIST SP 800-57 对称密钥等效安全强度，供安全策略和算法映射使用。

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_SECURITY_STRENGTH_112BIT | 112 | 112-bit，3DES 等效安全强度 |
| SCF_SECURITY_STRENGTH_128BIT | 128 | 128-bit，AES-128 等效安全强度 |
| SCF_SECURITY_STRENGTH_192BIT | 192 | 192-bit，AES-192 等效安全强度 |
| SCF_SECURITY_STRENGTH_256BIT | 256 | 256-bit，AES-256 等效安全强度 |

#### 1.1.32 TLS 命名组常量

以下字符串常量是 TLS 1.3 经典、后量子及混合密钥交换组名称。后量子组是否可用取决于运行时加载的
OpenSSL Provider。

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_NAMED_GROUP_X25519 | `"X25519"` | X25519，128-bit 经典安全强度 |
| SCF_NAMED_GROUP_P256 | `"P-256"` | ECDH P-256，128-bit 经典安全强度 |
| SCF_NAMED_GROUP_P384 | `"P-384"` | ECDH P-384，192-bit 经典安全强度 |
| SCF_NAMED_GROUP_P521 | `"P-521"` | ECDH P-521，256-bit 经典安全强度 |
| SCF_NAMED_GROUP_KYBER512 | `"kyber512"` | Kyber-512，NIST Level 1 |
| SCF_NAMED_GROUP_KYBER768 | `"kyber768"` | Kyber-768，NIST Level 3 |
| SCF_NAMED_GROUP_KYBER1024 | `"kyber1024"` | Kyber-1024，NIST Level 5 |
| SCF_NAMED_GROUP_MLKEM512 | `"mlkem512"` | FIPS 203 ML-KEM-512，NIST Level 1 |
| SCF_NAMED_GROUP_MLKEM768 | `"mlkem768"` | FIPS 203 ML-KEM-768，NIST Level 3 |
| SCF_NAMED_GROUP_MLKEM1024 | `"mlkem1024"` | FIPS 203 ML-KEM-1024，NIST Level 5 |
| SCF_NAMED_GROUP_P256_KYBER512 | `"p256_kyber512"` | ECDH P-256 + Kyber-512 混合组 |
| SCF_NAMED_GROUP_X25519_KYBER512 | `"x25519_kyber512"` | X25519 + Kyber-512 混合组 |
| SCF_NAMED_GROUP_P384_KYBER768 | `"p384_kyber768"` | ECDH P-384 + Kyber-768 混合组 |
| SCF_NAMED_GROUP_P521_KYBER1024 | `"p521_kyber1024"` | ECDH P-521 + Kyber-1024 混合组 |
| SCF_NAMED_GROUP_X25519_MLKEM512 | `"x25519_mlkem512"` | X25519 + ML-KEM-512 混合组 |
| SCF_NAMED_GROUP_P521_MLKEM1024 | `"p521_mlkem1024"` | ECDH P-521 + ML-KEM-1024 混合组 |

### 1.2 结构体

#### 1.2.1 文件上下文

##### 定义

```c++
typedef struct SCFFileCtx SCF_FILE_CTX;
```

##### 用途

文件上下文，在设置证书、私钥时作为文件内容承载使用。

##### 属性说明

- 内部结构体，外部不需要关心结构，可通过函数操作属性。
- 使用完成后需要调用[SCF_FileCtxFree](#222-SCF_FileCtxFree)进行资源释放

#### 1.2.2 安全策略上下文

##### 定义

```c++
typedef struct SCFPolicyCtx SCF_PolicyCtx;
```

##### 用途

安全策略上下文。在设置通信算法套、认证模式、证书等时，作为承载策略内容使用。

##### 属性说明

- 内部结构体，外部不需要关心结构，可通过函数操作属性。
- 使用完成后需要调用[SCF_FreePolicyCtx](#217-SCF_FreePolicyCtx)进行资源释放

#### 1.2.3 安全策略对象

##### 定义

```c++
typedef struct SCFPolicyObj SCF_PolicyObj;
```

##### 用途

安全策略对象实例，从[SCF_PolicyCtx](#122-安全策略上下文)创建

##### 属性说明

- 内部结构体，外部不需要关心结构，可通过函数操作属性。
- 一个<code>SCF_PolicyCtx</code>可以生成多个<code>SCF_PolicyObj</code>，每个<code>SCF_PolicyObj</code>对应一条链接
- 使用完成后需要调用[SCF_FreePolicyObj](#2112-SCF_FreePolicyObj)进行资源释放

#### 1.2.4 安全会话对象

##### 定义

```c++
typedef void SCF_Session;
```

##### 用途

安全会话对象，通过调用[SCF_SessionNew](#233-SCF_SessionNew)创建

##### 属性说明

- 内部结构体，外部不需要关心结构，可通过函数操作属性。
- 仅用于PSK回调函数中设置属性使用
- 使用完成后需要调用[SCF_SessionFree](#234-SCF_SessionFree)进行资源释放

#### 1.2.5 RBAC 策略规则

##### 定义

```c++
struct SCF_PolicyRule {
    uint32_t ruleId;
    std::string subjectNodeId;
    std::string targetNodeId;
    uint32_t resourceTypeBitmap;
    uint32_t actionBitmap;
    SCF_POLICY_EFFECT effect;
};
```

##### 用途

表示一条 RBAC 自定义策略规则，由[SCF_AddPolicyRule](#274-SCF_AddPolicyRule)创建，通过
[SCF_ListPolicyRules](#276-SCF_ListPolicyRules)读取。

##### 属性说明

| 名称 | 含义 |
|---|---|
| ruleId | 当前安全策略上下文内唯一且不复用的规则 ID |
| subjectNodeId | 发起资源操作的节点 ID |
| targetNodeId | 被操作的节点 ID 或通配符 `"*"` |
| resourceTypeBitmap | 资源类型位图，取值见[1.1.18 RBAC 资源类型](#1118-rbac-资源类型) |
| actionBitmap | 资源操作位图，取值见[1.1.17 RBAC 资源操作](#1117-rbac-资源操作) |
| effect | 规则效果，见[1.1.19 RBAC 策略效果](#1119-rbac-策略效果) |

#### 1.2.6 安全连接配置

`scf::SCFConnectionConfig` 用于创建高层安全连接。构造函数默认创建客户端配置，使用 128-bit 经典安全配置、
必须校验证书、默认 Socket 传输，且不指定自定义密码引擎工厂。

| 名称 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| kDefaultConnectTimeoutMs | `static constexpr uint32_t` | 5000 | 默认连接超时，单位 ms |
| kDefaultHandshakeTimeoutMs | `static constexpr uint32_t` | 10000 | 默认 TLS 握手超时，单位 ms |
| securityLevel | `SCF_SECURITY_LEVEL` | `SCF_SECURITY_128BIT` | 安全强度，见[1.1.20 连接安全强度](#1120-连接安全强度) |
| role | `SCF_ROLE` | `SCF_ROLE_CLIENT` | 通信角色 |
| caCertPath | `std::string` | 空 | CA 证书路径；校验对端时必填 |
| certPath | `std::string` | 空 | 本端设备证书路径 |
| keyPath | `std::string` | 空 | 本端私钥路径 |
| keyPassword | `std::string` | 空 | 私钥口令；空表示无口令 |
| crlPath | `std::string` | 空 | 可选 CRL 路径 |
| certVerifyPolicy | `SCF_CERT_VERIFY_POLICY` | `SCF_CERT_VERIFY_REQUIRED` | 证书校验策略 |
| pskIdentity | `std::string` | 空 | PSK 身份标识 |
| pskKey | `std::vector<uint8_t>` | 空 | PSK 密钥 |
| usePSK | `bool` | `false` | 是否使用与证书认证互斥的 PSK 模式 |
| transportFactory | `ITransportFactory *` | `nullptr` | 自定义传输工厂；空表示使用默认 Socket |
| cryptoEngineFactory | `ICryptoEngineFactory *` | `nullptr` | 自定义密码引擎工厂；空时尝试 KAE，KAE 不可用或初始化失败时不注入 `ICryptoEngine`，由 TLS 适配器使用常规 OpenSSL 软件路径 |
| appVerifyCb | `SCF_AppVerifyFunc` | `nullptr` | 可选的自定义证书校验回调 |
| appVerifyArg | `void *` | `nullptr` | 传给证书校验回调的用户数据 |
| connectTimeoutMs | `uint32_t` | 5000 | 连接超时，0 表示不超时 |
| handshakeTimeoutMs | `uint32_t` | 10000 | TLS 握手超时；当前实现保留该配置但尚未应用 |
| enableSessionResumption | `bool` | `true` | 是否启用会话恢复；当前实现保留该配置但尚未应用 |
| enableKeyAutoUpdate | `bool` | `true` | 是否启用自动密钥更新 |

#### 1.2.7 密码引擎能力

`scf::CryptoEngineCapability` 描述密码引擎身份、算法集合和硬件能力。

| 名称 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| engineName | `std::string` | 空 | 引擎名称 |
| engineVersion | `std::string` | 空 | 引擎版本 |
| hardwareVendor | `std::string` | 空 | 硬件厂商信息 |
| symmetricAlgos | `std::vector<SymmetricAlgorithm>` | 空 | 支持的对称算法 |
| asymmetricAlgos | `std::vector<AsymmetricAlgorithm>` | 空 | 支持的非对称算法 |
| hashAlgos | `std::vector<HashAlgorithm>` | 空 | 支持的哈希算法 |
| keyExchangeAlgos | `std::vector<KeyExchangeAlgorithm>` | 空 | 支持的密钥交换算法 |
| hardwareAccelerated | `bool` | `false` | 是否使用硬件加速 |
| supportsAsyncOperation | `bool` | `false` | 是否支持异步操作 |
| supportsOffload | `bool` | `false` | 是否支持计算卸载 |
| maxConcurrentOps | `uint32_t` | 0 | 最大并发操作数，0 表示不限制 |

#### 1.2.8 密码引擎配置

| `scf::CryptoEngineConfig` 名称 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| kDefaultSessionPoolSize | `static constexpr uint32_t` | 16 | 默认会话池大小 |
| kDefaultAsyncQueueDepth | `static constexpr uint32_t` | 64 | 默认异步队列深度 |
| configFilePath | `std::string` | 空 | 引擎配置文件路径 |
| devicePath | `std::string` | 空 | 硬件设备路径，如 `/dev/crypto` |
| sessionPoolSize | `uint32_t` | 16 | 会话池大小 |
| enableAsyncMode | `bool` | `false` | 是否启用异步模式 |
| asyncQueueDepth | `uint32_t` | 64 | 异步队列深度 |

#### 1.2.9 密钥句柄

`scf::CryptoKeyHandle` 引用存储在密码引擎或硬件中的密钥。

| 名称 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| keyId | `uint64_t` | 0 | 密钥 ID |
| keyLabel | `std::string` | 空 | 密钥标签 |
| engineContext | `void *` | `nullptr` | 引擎内部上下文 |

句柄由[ICryptoEngine::ImportKey](#2101-ICryptoEngine)写入，并通过 `DestroyKey` 销毁。

#### 1.2.10 传输端点地址

| `scf::TransportAddress` 名称 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| type | `TransportAddressType` | `TransportAddressType::IPv4` | 地址类型 |
| host | `std::string` | 空 | 主机、域名或后端自定义地址 |
| port | `uint16_t` | 0 | 端口 |

可通过构造函数直接填写字段，也可使用[TransportAddress 工厂方法](#2111-TransportAddress-工厂方法)。

#### 1.2.11 传输配置

| `scf::TransportConfig` 名称 | 类型 | 默认值 | 含义 |
|---|---|---|---|
| kDefaultConnectTimeoutMs | `static constexpr int32_t` | 5000 | 默认连接超时，单位 ms |
| nonBlocking | `bool` | `true` | 是否使用非阻塞模式 |
| sendTimeoutMs | `int32_t` | 0 | 发送超时，0 表示不设置 |
| recvTimeoutMs | `int32_t` | 0 | 接收超时，0 表示不设置 |
| connectTimeoutMs | `int32_t` | 5000 | 连接超时 |
| sendBufferSize | `size_t` | 0 | 发送缓冲区大小，0 表示使用系统默认值 |
| recvBufferSize | `size_t` | 0 | 接收缓冲区大小，0 表示使用系统默认值 |
| tcpNoDelay | `bool` | `true` | 是否启用 `TCP_NODELAY` |

### 1.3 回调函数定义

#### 1.3.1 ExternalLogFunction

##### 定义

```c++
typedef void (*ExternalLogFunction)(int level, const char *msg);
```

##### 用途

自定义日志函数格式

##### 输入

| 名称    | 含义                                  |
|-------|-------------------------------------|
| level | [IN]日志级别，见[1.1.10-日志级别](#1110-日志级别) |
| msg   | [IN]日志内容                            |

##### 输出

无

#### 1.3.2 ExternalDecryptFunction

##### 定义

```c++
using ExternalDecryptFunction = bool (*)(const uint8_t *content, size_t contentLen, std::vector<std::byte> &plaintext);
```

##### 用途

自定义解密函数格式，用于私钥文件密码及PSK MasterKey密文解密

##### 输入

| 名称         | 含义         |
|------------|------------|
| content    | [IN]密文内容   |
| contentLen | [IN]密文内容长度 |
| plaintext  | [OUT]明文内容  |

##### 输出

- true:解密成功
- false:解密失败

#### 1.3.3 SCF_AppVerifyFunc

##### 定义

```c++
typedef int32_t (*SCF_AppVerifyFunc)(void *storeCtx, void *arg);
```

##### 用途

用户校验回调，配置后，内部的证书认证检查会使用用户注册的实现，不使用默认实现

##### 输入

| 名称       | 含义                                                         |
|----------|------------------------------------------------------------|
| storeCtx | [IN]实际是底层 ssl 库的上下文，openssl时为<code>X509_STORE_CTX</code>结构 |
| arg      | [IN]用户数据                                                   |

##### 输出

见[1.4 错误码](#14-错误码)

#### 1.3.4 SCF_PskUseSessionCb

##### 定义

```c++
typedef int32_t (*SCF_PskUseSessionCb)(
    SCF_PolicyObj *obj, uint32_t hashAlgo, const uint8_t **id, uint32_t *idLen, SCF_Session **session);
```

##### 用途

客户端 tls1.3 psk 回调原型

##### 输入

| 名称       | 含义                                              |
|----------|-------------------------------------------------|
| obj      | [IN]安全策略上下文对象                                   |
| hashAlgo | [IN]tls 算法套的 hash 算法。注意 client hello 时输入的取值会是 0 |
| id       | [OUT]客户端给服务端的提示，服务端用于查找使用的 psk                  |
| idLen    | [OUT]id 的长度                                     |
| session  | [OUT]创建的会话对象                                    |

##### 输出

见[1.4 错误码](#14-错误码)

#### 1.3.5 SCF_PskFindSessionCb

##### 定义

```c++
typedef int32_t (*SCF_PskFindSessionCb)(
    SCF_PolicyObj *obj, const uint8_t *identity, uint32_t identityLen, SCF_Session **session);
```

##### 用途

服务端 tls1.3 psk 回调原型

- 由于PSK通常仅限于内部通信场景使用，推荐业务固定两端均配置为相同的一个算法套，保证协商使用的算法是相同的。
  服务端涉及和多个客户端对接时，建议对于hash算法不同的算法套，业务使用不同的上下文，降低客户端实现难度。
- 业务需要设计id的内容。例如idversion，PSKinfo等实现业务的版本对接兼容。

##### 输入

| 名称          | 含义                            |
|-------------|-------------------------------|
| obj         | [IN]安全策略上下文对象                 |
| identity    | [IN]客户端给服务端的提示，服务端用于查找使用的 psk |
| identityLen | [IN]id 的长度                    |
| session     | [OUT]创建的会话对象                  |

##### 输出

见[1.4 错误码](#14-错误码)

### 1.4 错误码

错误码由项目标识、模块标识和模块内编号按位组合。相关宏定义如下：

```c++
#define SCF_PROJECT_ID 0x75000000
#define SCF_MOD_MAKE(Mod) (SCF_PROJECT_ID | ((uint32_t)(Mod) << 8UL))
#define SCF_MOD_COMMON SCF_MOD_MAKE(0x0000)
#define SCF_MOD_CAL SCF_MOD_MAKE(0x0010)
#define SCF_SUBMOD_SSL_RETRY SCF_MOD_MAKE(0x0020)
#define SCF_SUBMOD_SSL SCF_MOD_MAKE(0x0021)
#define SCF_MOD_CONFIG SCF_MOD_MAKE(0x0011)
#define SCF_MOD_LOG SCF_MOD_MAKE(0x9000)
#define SCF_MOD_RBAC SCF_MOD_MAKE(0x0030)
#define SCF_ERRNO_MAKE(Mod, Errno) ((Mod) | (Errno))
```

| 名称 | 值 | 含义 |
|---|---|---|
| SCF_PROJECT_ID | `0x75000000` | SCF 项目标识 |
| SCF_MOD_COMMON | `0x75000000` | 通用错误模块 |
| SCF_MOD_CAL | `0x75001000` | CAL 模块 |
| SCF_MOD_CONFIG | `0x75001100` | 配置解析模块 |
| SCF_SUBMOD_SSL_RETRY | `0x75002000` | SSL 可重试错误子模块 |
| SCF_SUBMOD_SSL | `0x75002100` | SSL 错误子模块 |
| SCF_MOD_RBAC | `0x75003000` | RBAC 模块 |
| SCF_MOD_LOG | `0x75900000` | 日志模块 |

| 名称                                      | 值          | 含义                            |
|-----------------------------------------|------------|-------------------------------|
| SCF_SUCCESS                           | 0          | 操作成功。                         |
| SCF_ERROR                             | 1          | 操作失败。                         |
| SCF_ERRNO_NULL_INPUT                  | 1962934273 | 入参为null。                      |
| SCF_ERRNO_INVALID_PARAM               | 1962934274 | 入参无效。                         |
| SCF_ERRNO_MEM_ALLOC                   | 1962934275 | 内存分配失败。                       |
| SCF_ERRNO_MEM_CPY                     | 1962934276 | 内存拷贝失败。                       |
| SCF_ERRNO_NOT_SUPPORT                 | 1962934277 | 不支持。                          |
| SCF_ERRNO_INIT_BSM                    | 1962934278 | 初始化BSM失败。                     |
| SCF_ERRNO_LARGE_FILE                  | 1962934279 | 读取超大文件                        |
| SCF_ERRNO_SYSTEM_TIME_ERROR           | 1962934280 | 获取系统时间异常                      |
| SCF_ERRNO_FILE_PATH_ERROR             | 1962934281 | 获取文件路径异常                      |
| SCF_ERRNO_READ_FILE_ERROR             | 1962934282 | 获取文件异常                        |
| SCF_ERRNO_INIT_HITLS_BSL              | 1962938369 | 初始化HiTLS_BSL失败。               |
| SCF_ERRNO_INIT_HITLS_CRYPTO           | 1962938370 | 初始化HiTLS_CRYPTO失败。            |
| SCF_ERRNO_INIT_HITLS_TLS              | 1962938371 | 初始化HiTLS_TLS失败。               |
| SCF_ERRNO_NULL_HITLS_CTX              | 1962938372 | HITLS_CTX为null。               |
| SCF_ERRNO_NULL_HITLS_CFG              | 1962938373 | HITLS_CFG为null。               |
| SCF_ERRNO_SECURE_TRANSPORT            | 1962938374 | 安全传输错误。                       |
| SCF_ERRNO_INIT_OPENSSL                | 1962938375 | SSL_library_init()函数失败。       |
| SCF_ERRNO_INIT_OPENSSL_ERR            | 1962938376 | SSL_load_error_strings()函数失败。 |
| SCF_ERRNO_INIT_OPENSSL_CRYPTO         | 1962938377 | 初始化OpenSSL加解密失败。              |
| SCF_ERRNO_INIT_OPENSSL_ALGO           | 1962938378 | 初始化OpenSSL算法失败。               |
| SCF_ERRNO_NULL_CALLBACK               | 1962938379 | 没有回调。                         |
| SCF_ERRNO_TLS_ALREADY_INIT            | 1962938380 | TLS已初始化。                      |
| SCF_ERRNO_INVALID_TLS_TYPE            | 1962938381 | 无效的TLStype。                   |
| SCF_ERRNO_LOAD_LIB                    | 1962938382 | 加载lib错误。                      |
| SCF_ERRNO_UNLOAD_LIB                  | 1962938383 | 未加载lib。                       |
| SCF_ERRNO_LOAD_SYMBOL                 | 1962938384 | 加载符号失败                        |
| SCF_ERRNO_INIT_HITLS_PSE              | 1962938385 | 初始化失败，hitls pse 模块            |
| SCF_ERRNO_INIT_SECUREC                | 1962938386 | 初始化失败，securec 模块              |
| SCF_ERRNO_NOT_INIT                    | 1962938387 | 未初始化                          |
| SCF_ERRNO_RBAC_DISABLED               | 1962946561 | RBAC 鉴权未启用。                     |
| SCF_ERRNO_RBAC_DENIED                 | 1962946562 | 资源访问被拒绝。                      |
| SCF_ERRNO_RBAC_ROLE_UNKNOWN           | 1962946563 | 未能从证书或节点角色映射解析出角色。       |
| SCF_ERRNO_RBAC_NODE_ID_EMPTY          | 1962946564 | 节点 ID 为空。                        |
| SCF_ERRNO_RBAC_MAP_FULL               | 1962946565 | 节点角色映射已达到上限。       |
| SCF_ERRNO_RBAC_MAP_NOT_FOUND          | 1962946566 | 指定节点角色映射不存在。                 |
| SCF_ERRNO_CERT_NODE_ID_ABSENT         | 1962946567 | 证书缺少 NodeId 自定义扩展。             |
| SCF_ERRNO_CERT_ROLE_EXT_ABSENT        | 1962946568 | 证书缺少 RBAC 角色自定义扩展。            |
| SCF_ERRNO_RBAC_POLICY_NOT_FOUND       | 1962946569 | 指定 RBAC 策略规则不存在。                |
| SCF_ERRNO_RBAC_POLICY_FULL            | 1962946570 | RBAC 策略规则数量或规则 ID 已达到上限。    |
| SCF_ERRNO_RBAC_POLICY_DUPLICATE       | 1962946571 | RBAC 策略规则重复或效果冲突。              |
| SCF_ERRNO_RBAC_POLICY_INVALID         | 1962946572 | RBAC 策略规则参数非法。                   |
| SCF_ERRNO_RBAC_MAP_FROZEN             | 1962946573 | 连接成功建链后，节点角色映射已冻结。        |
| SCF_CFG_ERRNO_PARSE                   | 1962938625 | CFG解析失败。                      |
| SCF_CFG_ERRNO_CERT_ARRAY_GET          | 1962938626 | CFG获取证书列表失败。                  |
| SCF_CFG_ERRNO_CERT_ITEM_GET           | 1962938627 | CFG获取证书失败。                    |
| SCF_CFG_ERRNO_CERT_ADD                | 1962938628 | CFG添加证书失败。                    |
| SCF_CFG_ERRNO_PRIVKEY_GET             | 1962938629 | CFG获取私钥失败。                    |
| SCF_CFG_ERRNO_PRIVKEY_ADD             | 1962938630 | CFG添加私钥失败。                    |
| SCF_CFG_ERRNO_CIPHER_SUITES_ARRAY_GET | 1962938631 | CFG获取算法套列表失败。                 |
| SCF_CFG_ERRNO_CIPHER_SUITES_ITEM_GET  | 1962938632 | CFG获取算法套失败。                   |
| SCF_CFG_ERRNO_TLS_VERSION_GET         | 1962938633 | CFG获取TLS版本失败。                 |
| SCF_CFG_ERRNO_TLS_VERSION_SET         | 1962938634 | CFG设置TLS版本失败。                 |
| SCF_CFG_ERRNO_TLS_FORBID_VERSION_GET  | 1962938635 | CFG禁止的TLS版本。                  |
| SCF_CFG_ERRNO_KEY_UPDATE              | 1962938636 | CFG更新密钥失败。                    |
| SCF_SSL_ERR_SSL                       | 1962942465 | SSL错误。                        |
| SCF_SSL_ERR_WANT_READ                 | 1962942466 | SSL试图读失败。                     |
| SCF_SSL_ERR_WANT_WRITE                | 1962942467 | SSL试图写失败。                     |
| SCF_SSL_ERR_WANT_X509_LOOKUP          | 1962942468 | SSL查找X509失败。                  |
| SCF_SSL_ERR_SYSCALL                   | 1962942469 | SSL系统调用失败。                    |
| SCF_SSL_ERR_ZERO_RETURN               | 1962942470 | SSL返回0。                       |
| SCF_SSL_ERR_WANT_CONNECT              | 1962942471 | SSL试图连接失败。                    |
| SCF_SSL_ERR_WANT_ACCEPT               | 1962942472 | SSL试图接受失败。                    |
| SCF_SSL_ERR_WANT_ASYNC                | 1962942473 | SSL试图异步失败。                    |
| SCF_SSL_ERR_WANT_ASYNC_JOB            | 1962942474 | SSL试图异步JOB失败。                 |
| SCF_SSL_ERR_WANT_CLIENT_HELLO_CB      | 1962942475 | SSL试图客户端Hello回调失败。            |
| SCF_SSL_ERR_WANT_BACKEP               | 1962942476 | SSL试图backep失败。                |
| SCF_SSL_ERR_FORMAT_TYPE               | 1962942721 | SSL格式错误。                      |
| SCF_SSL_ERR_STORE_TYPE                | 1962942722 | SSL存储类型错误。                    |
| SCF_SSL_ERR_PARSE_CERT                | 1962942723 | SSL解析证书失败。                    |
| SCF_SSL_ERR_ADD_CERT_TO_STORE         | 1962942724 | SSL添加证书到存储失败。                 |
| SCF_SSL_ERR_LOAD_KEY                  | 1962942725 | SSL加载密钥失败。                    |
| SCF_SSL_ERR_PATH_TOO_LONG             | 1962942726 | SSL路径过长。                      |
| SCF_SSL_ERR_CHECK_PKEY                | 1962942727 | SSL检查私钥失败。                    |
| SCF_SSL_ERR_ROLE                      | 1962942728 | SSL角色错误。                      |
| SCF_SSL_ERR_INIT_TLS13                | 1962942729 | SSL初始化TLS1.3失败。               |
| SCF_SSL_ERR_PSK_CB_HASH               | 1962942730 | SSL PSK回调失败。                  |
| SCF_SSL_ERR_GET_VERSION               | 1962942731 | SSL获取版本失败。                    |
| SCF_SSL_ERR_PSK_MISMATCH              | 1962942732 | SSL PSK不相符。                   |
| SCF_SSL_ERR_VERSION                   | 1962942733 | SSL版本错误。                      |
| SCF_SSL_ERR_POLICY_VERSION            | 1962942734 | SSL policy版本错误。               |
| SCF_SSL_ERR_SET_PASS                  | 1962942735 | SSL设置Pass失败。                  |
| SCF_SSL_ERR_PARSE_KEY                 | 1962942736 | SSL解析密钥失败。                    |
| SCF_SSL_ERR_LOAD_CRL                  | 1962942737 | SSL加载CRL失败。                   |
| SCF_SSL_ERR_SET_ROLE                  | 1962942738 | SSL设置角色失败。                    |
| SCF_SSL_ERR_SESS_SET_CIPHER           | 1962942739 | SSL session设置算法失败。            |
| SCF_SSL_ERR_SESS_SET_KEY              | 1962942740 | SSL session设置密钥失败。            |
| SCF_SSL_ERR_SESS_SET_PROTOCOL_VER     | 1962942741 | SSL session设置协议版本失败。          |
| SCF_SSL_ERR_READ                      | 1962942742 | SSL读失败。                       |
| SCF_SSL_ERR_WRITE                     | 1962942743 | SSL写失败。                       |
| SCF_SSL_ERR_CLOSE                     | 1962942744 | SSL关闭失败。                      |
| SCF_SSL_ERR_SET_CIPHER                | 1962942745 | SSL设置算法失败。                    |
| SCF_SSL_ERR_SET_PROTOCOL_VER          | 1962942746 | SSL设置协议版本失败。                  |
| SCF_SSL_ERR_SET_VER_FORBID            | 1962942747 | SSL禁止设置版本。                    |
| SCF_SSL_ERR_GET_CIPHER                | 1962942748 | SSL获取算法失败。                    |
| SCF_SSL_ERR_ADD_CA_CERT_TO_STORE      | 1962942749 | SSL添加CA证书到存储失败。               |
| SCF_SSL_ERR_ADD_EE_CERT_TO_STORE      | 1962942750 | SSL添加EE证书到存储失败。               |
| SCF_SSL_ERR_ADD_CRL_TO_STORE          | 1962942751 | SSL添加CRL到存储失败。                |
| SCF_SSL_ERR_INIT_TLS                  | 1962942752 | SSL初始化TLS失败。                  |
| SCF_SSL_ERR_SET_SEC_LEVEL             | 1962942753 | SSL设置SEC LEVEL失败。             |
| SCF_SSL_ERR_SET_SESS_TICKET           | 1962942754 | SSL设置session ticket失败。        |
| SCF_SSL_ERR_SET_SOCKET_FD             | 1962942755 | SSL设置socket fd失败。             |
| SCF_SSL_ERR_SEC_LEVEL_MISMATCH        | 1962942756 | SSL SEC LEVEL不匹配。             |
| SCF_SSL_ERR_GET_CERT_STORE            | 1962942757 | SSL获取证书存储失败。                  |
| SCF_SSL_ERR_KEY_UPDATE                | 1962942758 | SSL密钥更新失败。                    |
| SCF_SSL_ERR_IS_INIT_FINISHED          | 1962942759 | SSL初始化完成失败。                   |
| SCF_SSL_ERR_SET_UPDATE_PARAM          | 1962942760 | SSL设置更新参数失败。                  |
| SCF_SSL_ERR_SET_CRL_CHECK_FLAGS       | 1962942761 | SSL设置CRL检测标识失败。               |
| SCF_SSL_ERR_LOAD_CA_CERT_CHAIN        | 1962942762 | SSL加载CA证书链失败。                 |
| SCF_SSL_ERR_ADD_EE_CHAIN_TO_STORE     | 1962942763 | SSL添加EE链到存储失败。                |
| SCF_SSL_ERR_X509_VERIFY_CHAIN         | 1962942764 | SSL X509验证证书链失败。              |
| SCF_SSL_ERR_SET_EX_DATA               | 1962942765 | SSL设置ex_data失败                |
| SCF_SSL_ERR_SESS_GET_CIPHER           | 1962942766 | SSL获取算法套失败                    |
| SCF_SSL_ERR_SESS_GET_PROTOCOL_VER     | 1962942767 | SSL获取协议版本号失败                  |
| SCF_SSL_ERR_CERT_EXT_ABSENT            | 1962942768 | 证书扩展字段不存在                    |

### 1.5 配置文件

#### 1.5.1 安全通信配置文件

##### 1.5.1.1 文件格式

```json
{
    "tlsVersion": {
        "minVersion": "SSL_VERSION_TLS12",
        "maxVersion": "SSL_VERSION_TLS13",
        "forbidVersion": ["SSL_VERSION_TLS13"]
    },
    "tlsCipherSuites": ["SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "SCF_SSL_AES_128_GCM_SHA256"],
    "certs": [
        {
            "cert": {
                "certType" : "CA",
                "storeBuf": "/path/to/cert_file"
            }
        }
    ],
    "privKey": {
        "storeBuf": "/path/to/key_file",
        "keyAuth": {
            "isCipher" : true,
            "storeBuf" : "auth_content"
        }
    }
}
```

##### 1.5.1.2 字段说明

| 参数名             | 参数类型        | 是否必选 | 描述                                                                   |
|-----------------|-------------|------|----------------------------------------------------------------------|
| tlsVersion      | JsonObject  | 否    | tls协议版本配置                                                            |
| -minVersion     | String      | 否    | tls协议最小版本配置，见[1.1.11 协议版本号_配置文件](#1111-协议版本号_配置文件)                   |
| -maxVersion     | String      | 否    | tls协议最大版本配置，见[1.1.11 协议版本号_配置文件](#1111-协议版本号_配置文件)                   |
| -forbidVersion  | StringArray | 否    | tls协议禁用版本配置，见[1.1.11 协议版本号_配置文件](#1111-协议版本号_配置文件)                   |
| tlsCipherSuites | StringArray | 否    | tls算法套配置，见[1.1.12 协议算法套_配置文件](#1112-协议算法套_配置文件)                      |
| certs           | JsonArray   | 否    | 证书文件                                                                 |
| -cert           | JsonObject  | 否    | 证书文件，**仅支持PEM格式证书**                                                  |
| --certType      | String      | 否    | 证书用途，见[1.1.13 证书用途_配置文件](#1113-证书用途_配置文件)                            |
| --storeBuf      | String      | 否    | 证书文件路径，**绝对路径**                                                      |
| privKey         | JsonObject  | 否    | 私钥文件，**仅支持PEM格式私钥**                                                  |
| -storeBuf       | JsonObject  | 否    | 私钥文件路径，**绝对路径**                                                      |
| -keyAuth        | JsonObject  | 否    | 私钥文件密码                                                               |
| --isCipher      | bool        | 否    | 是为否密文<br/><code>true</code>-是（密码为密文）<br/><code>false</code>-否（密码为明文） |
| --storeBuf      | String      | 否    | 私钥文件密码                                                               |

## 2 API接口

### 2.1 安全策略模块

#### 2.1.1 SetExternalLogFunction

##### 函数定义

设置自定义日志函数。

##### 实现方法

```c++
void SetExternalLogFunction(ExternalLogFunction func);
```

##### 参数说明

| 参数名  | 参数类型 | 是否必选 | 描述                                                                     |
|------|------|------|------------------------------------------------------------------------|
| func | [IN] | 是    | 自定义日志回调函数，见[2.1.1 SetExternalLogFunction](#211-SetExternalLogFunction) |

##### 返回值

void。

#### 2.1.2 GetErrorMessage

##### 函数定义

获取错误码对应的信息。

##### 实现方法

```c++
const char *GetErrorMessage(int32_t errorCode);
```

##### 参数说明

| 参数名       | 参数类型 | 是否必选 | 描述                      |
|-----------|------|------|-------------------------|
| errorCode | [IN] | 是    | 错误码，见[1.4 错误码](#14-错误码) |

##### 返回值

错误信息。

#### 2.1.3 SetExternalDecryptFunction

##### 函数定义

设置自定义解密函数，如果密码涉及到加密时需要先设置对应解密回调。

##### 实现方法

```c++
void SetExternalDecryptFunction(ExternalDecryptFunction func);
```

##### 参数说明

| 参数名  | 参数类型 | 是否必选 | 描述                                                                    |
|------|------|------|-----------------------------------------------------------------------|
| func | [IN] | 是    | 解密函数实现，见[1.3.2 ExternalDecryptFunction](#132-ExternalDecryptFunction) |

##### 返回值

无。

#### 2.1.4 SCF_Init

##### 函数定义

初始化 SCF 模块，可以通过指定初始化底层TLS模块。
本接口调用后 SCF 模块功能才可以使用，仅需要在进程启动时调用一次即可，无需重复调用。
与[SCF_DeInit](#215-SCF_DeInit)配套使用。

##### 实现方法

```c++
int32_t SCF_Init(uint64_t flag, void *settings);
```

##### 参数说明

| 参数名      | 参数类型 | 是否必选 | 描述                                                                            |
|----------|------|------|-------------------------------------------------------------------------------|
| flag     | [IN] | 是    | 初始化选项，见[1.1.1 初始化类型](#111-初始化类型)                                              |
| settings | [IN] | 是    | 初始化配置，初始化的TLS对应动态依赖库所在路径<br/>使用Openssl初始化时，路径下需要包含libssl.so及libcrypto.so两个动态库 |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.5 SCF_DeInit

##### 函数定义

去初始化 SCF 模块。与[SCF_Init](#214-SCF_Init)配套使用。本接口调用后 SCF 模块不可用，故仅需要在进程消亡时调用一次即可。

##### 实现方法

```c++
void SCF_DeInit(void);
```

##### 参数说明

无。

##### 返回值

无。

#### 2.1.6 SCF_CreatePolicyCtx

##### 函数定义

安全策略上下文，使用完成后需要调用[SCF_FreePolicyCtx](#217-SCF_FreePolicyCtx)释放。

##### 实现方法

```c++
SCF_PolicyCtx *SCF_CreatePolicyCtx(void);
```

##### 参数说明

无。

##### 返回值

安全策略实例，见[1.2.2 安全策略上下文](#122-安全策略上下文)，异常返回<code>nullptr</code>

#### 2.1.7 SCF_FreePolicyCtx

##### 函数定义

释放安全通信上下文。与[SCF_CreatePolicyCtx](#216-SCF_CreatePolicyCtx)配对使用。

##### 实现方法

```c++
void SCF_FreePolicyCtx(SCF_PolicyCtx **ctx);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                     |
|-----|------|------|----------------------------------------|
| ctx | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |

##### 返回值

无。调用后会将ctx指向安全策略上下文置为<code>nullptr</code>。

#### 2.1.8 SCF_SetPolicy

##### 函数定义

设置安全通信上下文。

##### 实现方法

```c++
int32_t SCF_SetPolicy(SCF_PolicyCtx *ctx, SCF_ROLE role, uint32_t verifyMode, SCF_POLICY_MODE policyMode);
```

##### 参数说明

| 参数名        | 参数类型 | 是否必选 | 描述                                                              |
|------------|------|------|-----------------------------------------------------------------|
| ctx        | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                          |
| role       | [IN] | 是    | 通信角色，见[1.1.4 通信角色](#114-通信角色)。默认值是none，需要用户指定是作为client还是server。 |
| verifyMode | [IN] | 是    | 校验模式，见[1.1.5 校验模式](#115-校验模式)                                   |
| policyMode | [IN] | 是    | 安全校验策略模式，见[1.1.6 安全策略等级](#116-安全策略等级)                           |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.9 SCF_GetPolicy

##### 函数定义

获取安全通信策略模式。

##### 实现方法

```c++
int32_t SCF_GetPolicy(SCF_PolicyCtx *ctx, SCF_ROLE *role, uint32_t *verifyMode, SCF_POLICY_MODE *policyMode);
```

##### 参数说明

| 参数名        | 参数类型  | 是否必选 | 描述                                                              |
|------------|-------|------|-----------------------------------------------------------------|
| ctx        | [IN]  | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                          |
| role       | [OUT] | 是    | 通信角色，见[1.1.4 通信角色](#114-通信角色)。默认值是none，需要用户指定是作为client还是server。 |
| verifyMode | [OUT] | 是    | 校验模式，见[1.1.5 校验模式](#115-校验模式)                                   |
| policyMode | [OUT] | 是    | 安全校验策略模式，见[1.1.6 安全策略等级](#116-安全策略等级)                           |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.10 SCF_SetConfigFile

##### 函数定义

配置安全通信策略的配置文件。方便集成方通过文件，批量设置安全策略接口能力。

##### 实现方法

```c++
int32_t SCF_SetConfigFile(SCF_PolicyCtx *ctx, const char *config);
```

##### 参数说明

| 参数名    | 参数类型 | 是否必选 | 描述                                                      |
|--------|------|------|---------------------------------------------------------|
| ctx    | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                  |
| config | [IN] | 是    | 配置文件路径。**绝对路径**。 文件内容格式见[1.5.1 安全通信配置文件](#151-安全通信配置文件) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.11 SCF_CreatePolicyObj

##### 函数定义

创建安全策略对象实例，使用完成后需要调用[SCF_FreePolicyObj](#2112-SCF_FreePolicyObj)释放。

##### 实现方法

```c++
SCF_PolicyObj *SCF_CreatePolicyObj(SCF_PolicyCtx *ctx);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                     |
|-----|------|------|----------------------------------------|
| ctx | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |

##### 返回值

安全策略实例，见[安全策略对象](#123-安全策略对象)，异常返回<code>nullptr</code>

#### 2.1.12 SCF_FreePolicyObj

##### 函数定义

释放安全通信对象实例。与[SCF_CreatePolicyObj](#2111-SCF_CreatePolicyObj)配对使用。

##### 实现方法

```c++
void SCF_FreePolicyObj(SCF_PolicyObj **obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

无。调用后会将obj指向安全策略对象置为<code>nullptr</code>。

#### 2.1.13 SCF_SetCipherSuites

##### 函数定义

配置安全通信使用的算法套。用户需要将安全性高的作为高优先级套件排在前面。内部实现是根据顺序协商的，优先协商排在前面的。

##### 实现方法

```c++
int32_t SCF_SetCipherSuites(SCF_PolicyCtx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize);
```

##### 参数说明

| 参数名              | 参数类型 | 是否必选 | 描述                                     |
|------------------|------|------|----------------------------------------|
| ctx              | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |
| cipherSuites     | [IN] | 是    | 算法套数组，见[1.1.9 通信算法套](#119-通信算法套)       |
| cipherSuitesSize | [IN] | 是    | cipherSuites的数量                        |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.14 SCF_GetCipherSuites

##### 函数定义

获取加密算法套。

##### 实现方法

```c++
int32_t SCF_GetCipherSuites(SCF_PolicyCtx *ctx, uint16_t *data, uint32_t dataLen, uint32_t *cipherSuitesSize);
```

##### 参数说明

| 参数名              | 参数类型     | 是否必选 | 描述                                     |
|------------------|----------|------|----------------------------------------|
| ctx              | [IN]     | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |
| data             | [IN/OUT] | 是    | 加密算法套的数据，见[1.1.9 通信算法套](#119-通信算法套)    |
| dataLen          | [IN]     | 是    | 缓冲区长度，预置长度                             |
| cipherSuitesSize | [OUT]    | 是    | 加密算法套的数据长度，实际长度                        |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.15 SCF_SetAppVerifyCallback

##### 函数定义

配置安全通信的校验回调。配置后，内部的证书认证检查会使用用户注册的实现，不使用默认实现。

##### 实现方法

```c++
int32_t SCF_SetAppVerifyCallback(SCF_PolicyCtx *ctx, SCF_AppVerifyFunc cb, void *arg);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                                               |
|-----|------|------|------------------------------------------------------------------|
| ctx | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                           |
| cb  | [IN] | 是    | 用户的认证校验实现，见[1.3.3 SCF_AppVerifyFunc](#133-SCF_AppVerifyFunc) |
| arg | [IN] | 是    | 用户数据                                                             |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.16 SCF_SetProtocolVersion

##### 函数定义

配置安全通信的协议版本号。

##### 实现方法

```c++
int32_t SCF_SetProtocolVersion(SCF_PolicyCtx *ctx, uint32_t minVersion, uint32_t maxVersion,
                                 uint32_t *forbidVersion, uint32_t forbidVersionLen);
```

##### 参数说明

| 参数名              | 参数类型 | 是否必选 | 描述                                     |
|------------------|------|------|----------------------------------------|
| ctx              | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |
| minVersion       | [IN] | 是    | 最低版本，见[1.1.2 协议版本号](#112-协议版本号)        |
| maxVersion       | [IN] | 是    | 最高版本，见[1.1.2 协议版本号](#112-协议版本号)        |
| forbidVersion    | [IN] | 是    | 禁用版本数组，见[1.1.2 协议版本号](#112-协议版本号)      |
| forbidVersionLen | [IN] | 是    | 禁用版本数组的长度                              |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.1.17 SCF_GetProtocolVersion

##### 函数定义

获取当前协商的协议版本号。仅在协商建链成功后，可以获取到版本号。

##### 实现方法

```c++
const char *SCF_GetProtocolVersion(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

当前协议版本号，见[1.1.14 协议版本号_字符串](#1114-协议版本号_字符串)

#### 2.1.18 SCF_FreeBuffer

##### 函数定义

释放查询接口返回的buffer资源。

##### 实现方法

```c++
void SCF_FreeBuffer(char **buffer, size_t &bufferLen);
```

##### 参数说明

| 参数名       | 参数类型 | 是否必选 | 描述        |
|-----------|------|------|-----------|
| buffer    | [IN] | 是    | 需要清理的资源   |
| bufferLen | [IN] | 是    | 需要清理的资源长度 |

##### 返回值

无。释放后<code>buffer</code>会置为<code>nullptr</code>，<code>bufferLen</code>会置为<code>0</code>

### 2.2 安全凭据证书

#### 2.2.1 SCF_FileCtxNew

##### 函数定义

创建文件上下文。使用完成后需要调用[SCF_FileCtxFree](#222-SCF_FileCtxFree)释放。

##### 实现方法

```c++
SCF_FILE_CTX *SCF_FileCtxNew(void);
```

##### 参数说明

无。

##### 返回值

文件上下文，见[1.2.1 文件上下文](#121-文件上下文)，异常返回<code>nullptr</code>

#### 2.2.2 SCF_FileCtxFree

##### 函数定义

释放[SCF_FILE_CTX](#121-文件上下文)对象的内存。需要与[SCF_FileCtxNew](#221-SCF_FileCtxNew)成对出现。

##### 实现方法

```c++
void SCF_FileCtxFree(SCF_FILE_CTX **ctx);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                               |
|-----|------|------|----------------------------------|
| ctx | [IN] | 是    | 文件上下文，见[1.2.1 文件上下文](#121-文件上下文) |

##### 返回值

调用后会将ctx指向文件上下文置为<code>nullptr</code>。

#### 2.2.3 SCF_FileCtxSetBuf

##### 函数定义

配置文件上下文存储的信息。

##### 实现方法

```c++
int32_t SCF_FileCtxSetBuf(SCF_FILE_CTX *ctx, SCF_STORE_TYPE storeType, uint8_t *buf, size_t bufLen,
                            SCF_STORE_FORMAT format);
```

##### 参数说明

| 参数名       | 参数类型 | 是否必选 | 描述                                            |
|-----------|------|------|-----------------------------------------------|
| ctx       | [IN] | 是    | 文件上下文，见[1.2.1 文件上下文](#121-文件上下文)              |
| storeType | [IN] | 是    | 数据存储方式类型，见[1.1.3 文件存储类型](#113-文件存储类型)         |
| buf       | [IN] | 是    | 数据内容。根据 storeType 不同，应该分别是文件路径或buffer         |
| bufLen    | [IN] | 是    | buf 的长度。文件路径时，最大路径长度为4096（有效长度4095 + '\0'结束符） |
| format    | [IN] | 是    | 数据存储的格式，见[1.1.7 证书格式类型](#117-证书格式类型)          |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.2.4 SCF_FileCtxSetPwd

##### 函数定义

私钥加密存储时，通过此接口配置证书私钥配套的口令。

##### 实现方法

```c++
int32_t SCF_FileCtxSetPwd(SCF_FILE_CTX *ctx, uint8_t *passwd, const size_t passwdLen, bool isCipher = false);
```

##### 参数说明

| 参数名       | 参数类型 | 是否必选 | 描述                                                                                           |
|-----------|------|------|----------------------------------------------------------------------------------------------|
| ctx       | [IN] | 是    | 文件上下文，见[1.2.1 文件上下文](#121-文件上下文)                                                             |
| passwd    | [IN] | 是    | 密钥缓冲区，存放口令内容，当是密文的时候，会解密成明文再使用                                                               |
| passwdLen | [IN] | 是    | passwd口令长度                                                                                   |
| isCipher  | [IN] | 否    | 是否为密文<br/><code>true</code>-是（密码为密文）<br/><code>false</code>-否（密为明文）<br/>默认<code>false</code> |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

> 注意
> > 1、本接口需要配合[2.2.6 SCF_SetKey](#226-SCF_SetKey)
> > 接口使用。通过此接口，将口令设置到和私钥同一个[SCF_FILE_CTX](#121-文件上下文)结构体对象中<br/>
> > 2、如果passwd为密文，需要提前调用[2.1.3 SetExternalDecryptFunction](#213-SetExternalDecryptFunction)配置解密回调<br/>
> > 3、passwd 字段包含敏感信息，使用完ctx后，需调用[2.2.2 SCF_FileCtxFree](#222-SCF_FileCtxFree)接口释放ctx，并清理passwd内存。

#### 2.2.5 SCF_AddCert

##### 函数定义

配置安全通信的证书。
如果存在单个文件中有多个type对象类型（例如pem格式允许同时存在CA证书/设备证书/证书链/CRL），用户需要先将文件内容按type对象分开。
对于同一类对象，规格上支持单个pem文件有多个CA证书，或单个 pem文件有多个CRL对象。有多个设备证书时，固定只会取第一个证书作为设备证书。
使用结束后，需要主动释放certCtx资源。

##### 实现方法

```c++
int32_t SCF_AddCert(SCF_PolicyCtx *ctx, SCF_FILE_CTX *certCtx, SCF_CERT_TYPE type);
```

##### 参数说明

| 参数名     | 参数类型 | 是否必选 | 描述                                     |
|---------|------|------|----------------------------------------|
| ctx     | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |
| certCtx | [IN] | 是    | 证书文件上下文，见[1.2.1 文件上下文](#121-文件上下文)     |
| type    | [IN] | 是    | 证书用途，见[1.1.8 证书用途](#118-证书用途)          |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.2.6 SCF_SetKey

##### 函数定义

配置安全通信的密钥。
如果存在单个文件中有多个私钥对象（例如 pem 格式允许同时存在多个私钥），固定只会取第一个私钥作为设备证书对应的密钥。
不支持混合了证书/公钥/私钥等对象的文件，仅支持单个私钥文件，如使用混合了证书/公钥/私钥等对象的文件，不保证接口的合法性。

##### 实现方法

```c++
int32_t SCF_SetKey(SCF_PolicyCtx *ctx, SCF_FILE_CTX *keyCtx);
```

##### 参数说明

| 参数名    | 参数类型 | 是否必选 | 描述                                     |
|--------|------|------|----------------------------------------|
| ctx    | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |
| keyCtx | [IN] | 是    | 私钥文件上下文，见[1.2.1 文件上下文](#121-文件上下文)     |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.2.7 SCF_CheckPrivateKey

##### 函数定义

公私钥匹配检查。检查已经加载的证书和密钥是否匹配。

##### 实现方法

```c++
int32_t SCF_CheckPrivateKey(SCF_PolicyCtx *ctx);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                     |
|-----|------|------|----------------------------------------|
| ctx | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

> 注意
> > 1、调用本接口前需要先调用[2.2.5 SCF_AddCert](#225-SCF_AddCert)、[2.2.6 SCF_SetKey](#226-SCF_SetKey)接口配置证书及私钥。

#### 2.2.8 SCF_GetCurrentCert

##### 函数定义

获取通信链路中本端的证书对象。使用完成后需要调用[2.2.10 SCF_FreeCert](#2210-SCF_FreeCert)进行资源释放。

##### 实现方法

```c++
void *SCF_GetCurrentCert(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

指向本端证书对象的指针。<br/>
可通过[2.2.11 SCF_GetCertVersion](#2211-SCF_GetCertVersion)获取证书版本，
[2.2.12 SCF_GetCertStartTime](#2212-SCF_GetCertStartTime)获取证书生效时间，
[2.2.13 SCF_GetCertEndTime](#2213-SCF_GetCertEndTime)获取证书失效时间，
[2.2.14 SCF_GetCertSerialNumber](#2214-SCF_GetCertSerialNumber)获取证书序列号

#### 2.2.9 SCF_GetPeerCert

##### 函数定义

获取通信链路中对端的证书对象。使用完成后需要调用[2.2.10 SCF_FreeCert](#2210-SCF_FreeCert)进行资源释放。

##### 实现方法

```c++
void *SCF_GetPeerCert(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

指向对端证书对象的指针。<br/>
可通过[2.2.11 SCF_GetCertVersion](#2211-SCF_GetCertVersion)获取证书版本，
[2.2.12 SCF_GetCertStartTime](#2212-SCF_GetCertStartTime)获取证书生效时间，
[2.2.13 SCF_GetCertEndTime](#2213-SCF_GetCertEndTime)获取证书失效时间，
[2.2.14 SCF_GetCertSerialNumber](#2214-SCF_GetCertSerialNumber)获取证书序列号

#### 2.2.10 SCF_FreeCert

##### 函数定义

用于释放[SCF_GetCurrentCert](#228-SCF_GetCurrentCert)和[SCF_GetPeerCert](#229-SCF_GetPeerCert)获取到的证书对象资源。

##### 实现方法

```c++
void SCF_FreeCert(void **cert);
```

##### 参数说明

| 参数名  | 参数类型 | 是否必选 | 描述         |
|------|------|------|------------|
| cert | [IN] | 是    | 指向证书结构体的指针 |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)，调用后会将cert指向证书对象置为<code>nullptr</code>。

#### 2.2.11 SCF_GetCertVersion

##### 函数定义

获取当前证书对象的证书版本。

##### 实现方法

```c++
int32_t SCF_GetCertVersion(const void *cert);
```

##### 参数说明

| 参数名  | 参数类型 | 是否必选 | 描述         |
|------|------|------|------------|
| cert | [IN] | 是    | 指向证书结构体的指针 |

##### 返回值

| 名称     | 值  | 含义         |
|--------|----|------------|
| x509v1 | 0  | x509v1证书版本 |
| x509v2 | 1  | x509v2证书版本 |
| x509v3 | 2  | x509v3证书版本 |
| -1     | -1 | 获取版本失败     |

#### 2.2.12 SCF_GetCertStartTime

##### 函数定义

获取当前证书的生效时间。

##### 实现方法

```c++
int32_t SCF_GetCertStartTime(const void *cert, char *certStartTimeBuffer, size_t bufferLen);
```

##### 参数说明

| 参数名                 | 参数类型     | 是否必选 | 描述                     |
|---------------------|----------|------|------------------------|
| cert                | [IN]     | 是    | 指向证书结构体的指针             |
| certStartTimeBuffer | [IN/OUT] | 是    | 证书开始时间buffer，需要调用方申请空间 |
| bufferLen           | [IN]     | 是    | buffer长度，建议不超过25个字符长度  |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.2.13 SCF_GetCertEndTime

##### 函数定义

获取当前证书的失效时间。

##### 实现方法

```c++
int32_t SCF_GetCertEndTime(const void *cert, char *certEndTimeBuffer, size_t bufferLen);
```

##### 参数说明

| 参数名               | 参数类型     | 是否必选 | 描述                     |
|-------------------|----------|------|------------------------|
| cert              | [IN]     | 是    | 指向证书结构体的指针             |
| certEndTimeBuffer | [IN/OUT] | 是    | 证书结束时间buffer，需要调用方申请空间 |
| bufferLen         | [IN]     | 是    | buffer长度，建议不超过25个字符长度  |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.2.14 SCF_GetCertSerialNumber

##### 函数定义

获取证书的序列号。

##### 实现方法

```c++
uint8_t *SCF_GetCertSerialNumber(const void *cert, uint32_t *dataLen);
```

##### 参数说明

| 参数名     | 参数类型  | 是否必选 | 描述              |
|---------|-------|------|-----------------|
| cert    | [IN]  | 是    | 指向证书结构体的指针      |
| dataLen | [OUT] | 是    | 指向证书序列号字符串长度的指针 |

##### 返回值

指向证书序列号字符串的指针，读完不需要释放。

### 2.3 安全凭据PSK

#### 2.3.1 SCF_SetPskFindSessionCallback

##### 函数定义

配置服务端 TLS 1.3PSK回调。

##### 实现方法

```c++
int32_t SCF_SetPskFindSessionCallback(SCF_PolicyCtx *ctx, SCF_PskFindSessionCb cb);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                                                                        |
|-----|------|------|-------------------------------------------------------------------------------------------|
| ctx | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                                                    |
| cb  | [IN] | 是    | psk回调，可为<code>nullptr</code>，见[1.3.5 SCF_PskFindSessionCb](#135-SCF_PskFindSessionCb) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.2 SCF_SetPskUseSessionCallback

##### 函数定义

配置客户端 TLS 1.3PSK回调。

##### 实现方法

```c++
int32_t SCF_SetPskUseSessionCallback(SCF_PolicyCtx *ctx, SCF_PskUseSessionCb cb);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                                                                      |
|-----|------|------|-----------------------------------------------------------------------------------------|
| ctx | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                                                  |
| cb  | [IN] | 是    | psk回调，可为<code>nullptr</code>，见[1.3.4 SCF_PskUseSessionCb](#134-SCF_PskUseSessionCb) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.3 SCF_SessionNew

##### 函数定义

创建PSK会话对象。使用完成后需要调用[2.3.4 SCF_SessionFree](#234-SCF_SessionFree)进行释放。

##### 实现方法

```c++
SCF_Session *SCF_SessionNew(void);
```

##### 参数说明

无。

##### 返回值

返回[SCF_Session](#124-安全会话对象)对象指针，异常返回<code>nullptr</code>

#### 2.3.4 SCF_SessionFree

##### 函数定义

释放[SCF_SessionNew](#233-SCF_SessionNew)创建的会话对象。

##### 实现方法

```c++
void SCF_SessionFree(SCF_Session **sess);
```

##### 参数说明

| 参数名  | 参数类型 | 是否必选 | 描述                                   |
|------|------|------|--------------------------------------|
| sess | [IN] | 是    | SSL会话对象，见[1.2.4 安全会话对象](#124-安全会话对象) |

##### 返回值

无。调用后会将sess指向SSL会话对象置为<code>nullptr</code>。

#### 2.3.5 SCF_SessionSetMasterKey

##### 函数定义

配置SSL会话对象的PSK原始物料。通信PSK会基于此物料派生。

##### 实现方法

```c++
int32_t SCF_SessionSetMasterKey(SCF_Session *sess, const uint8_t *masterKey, size_t masterKeyLen,
                                  bool isCipher = false);
```

##### 参数说明

| 参数名          | 参数类型 | 是否必选 | 描述                                                                                           |
|--------------|------|------|----------------------------------------------------------------------------------------------|
| sess         | [IN] | 是    | SSL会话对象，见[1.2.4 安全会话对象](#124-安全会话对象)                                                         |
| masterKey    | [IN] | 是    | 密钥物料。通信PSK会基于此物料派生, 需要调用方自行释放内存                                                              |
| masterKeyLen | [IN] | 是    | 密钥物料长度                                                                                       |
| isCipher     | [IN] | 否    | 是否为密文<br/><code>true</code>-是（密码为密文）<br/><code>false</code>-否（密为明文）<br/>默认<code>false</code> |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.6 SCF_SessionSetCipher

##### 函数定义

配置PSK会话对象的算法套。

##### 实现方法

```c++
int32_t SCF_SessionSetCipher(SCF_Session *sess, const void *cipherSuite, size_t cipherLen);
```

##### 参数说明

| 参数名         | 参数类型 | 是否必选 | 描述                                   |
|-------------|------|------|--------------------------------------|
| sess        | [IN] | 是    | SSL会话对象，见[1.2.4 安全会话对象](#124-安全会话对象) |
| cipherSuite | [IN] | 是    | TLS 算法套数组，见[1.1.9 通信算法套](#119-通信算法套) |
| cipherLen   | [IN] | 是    | TLS 算法套数组长度                          |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.7 SCF_SessionGetCipher

##### 函数定义

获取SSL会话对象的算法套。用于用户自定义校验内容。
使用完成后需要调用[SCF_SessionFreeCipher](#238-SCF_SessionFreeCipher)进行资源释放。

##### 实现方法

```c++
int32_t SCF_SessionGetCipher(SCF_Session *sess, void **cipherSuite, size_t &cipherLen);
```

##### 参数说明

| 参数名         | 参数类型  | 是否必选 | 描述                                   |
|-------------|-------|------|--------------------------------------|
| sess        | [IN]  | 是    | SSL会话对象，见[1.2.4 安全会话对象](#124-安全会话对象) |
| cipherSuite | [OUT] | 是    | TLS 算法套数组，见[1.1.9 通信算法套](#119-通信算法套) |
| cipherLen   | [OUT] | 是    | TLS 算法套数组长度                          |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.8 SCF_SessionFreeCipher

##### 函数定义

释放[SCF_SessionGetCipher](#237-SCF_SessionGetCipher)接口查询的算法套数组资源。

##### 实现方法

```c++
void SCF_SessionFreeCipher(void **cipherSuite, size_t &cipherLen);
```

##### 参数说明

| 参数名         | 参数类型 | 是否必选 | 描述                                   |
|-------------|------|------|--------------------------------------|
| cipherSuite | [IN] | 是    | TLS 算法套数组，见[1.1.9 通信算法套](#119-通信算法套) |
| cipherLen   | [IN] | 是    | TLS 算法套数组长度                          |

##### 返回值

无。释放后<code>cipherSuite</code>会置为<code>nullptr</code>，<code>cipherLen</code>会置为<code>0</code>

#### 2.3.9 SCF_SessionSetProtocolVersion

##### 函数定义

配置PSK会话对象的协议版本。

##### 实现方法

```c++
int32_t SCF_SessionSetProtocolVersion(SCF_Session *sess, const char *version);
```

##### 参数说明

| 参数名     | 参数类型 | 是否必选 | 描述                                        |
|---------|------|------|-------------------------------------------|
| sess    | [IN] | 是    | SSL会话对象，见[1.2.4 安全会话对象](#124-安全会话对象)      |
| version | [IN] | 是    | 协议版本，见[1.1.14 协议版本号_字符串](#1114-协议版本号_字符串) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.10 SCF_SessionGetProtocolVersion

##### 函数定义

获取SSL会话对象的协议版本。用于用户自定义校验内容，使用完成后需要调用[SCF_FreeBuffer](#2118-SCF_FreeBuffer)进行资源释放。

##### 实现方法

```c++
int32_t SCF_SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen);
```

##### 参数说明

| 参数名        | 参数类型  | 是否必选 | 描述                                        |
|------------|-------|------|-------------------------------------------|
| sess       | [IN]  | 是    | SSL会话对象，见[1.2.4 安全会话对象](#124-安全会话对象)      |
| version    | [OUT] | 是    | 协议版本，见[1.1.14 协议版本号_字符串](#1114-协议版本号_字符串) |
| versionLen | [OUT] | 是    | 协议版本内容长度                                  |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.11 SCF_CipherFind

##### 函数定义

查找算法套对象。

##### 实现方法

```c++
const void *SCF_CipherFind(SCF_PolicyObj *obj, uint8_t *cipherId);
```

##### 参数说明

| 参数名      | 参数类型 | 是否必选 | 描述                                    |
|----------|------|------|---------------------------------------|
| obj      | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |
| cipherId | [IN] | 是    | 算法套id对象，只支持1个。若客户需要查找多个，需要自行封装循环调用。   |

> 注意
> > 对单个算法套id（见[1.1.9 通信算法套](#119-通信算法套)），转为uint8数组后传入。<br/>
> > 以<code>SCF_SSL_AES_128_GCM_SHA256</code>为例，用法如下：
> > ```c++
> > uint8_t cipherId[] = {0x13, 0x01}; // SCF_SSL_AES_128_GCM_SHA256
> > auto  cipherSuite = SCF_CipherFind(obj, cipherId);
> > ```

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.12 SCF_SetUserData

##### 函数定义

设置用户自定义数据。用于用户自定义校验内容。

##### 实现方法

```c++
int32_t SCF_SetUserData(SCF_PolicyObj *obj, void *userData);
```

##### 参数说明

| 参数名      | 参数类型 | 是否必选 | 描述                                    |
|----------|------|------|---------------------------------------|
| obj      | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |
| userData | [IN] | 是    | 指向用户自定义数据的指针                          |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.3.13 SCF_GetUserData

##### 函数定义

获取用户自定义数据。

##### 实现方法

```c++
void *SCF_GetUserData(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

指向用户自定义数据的指针。

### 2.4 安全密钥更新

#### 2.4.1 SCF_SetKeyAutoUpdateParam

##### 函数定义

设置会话密钥更新的流量和时间阈值。

##### 实现方法

```c++
int32_t SCF_SetKeyAutoUpdateParam(SCF_PolicyCtx *ctx, bool isNeedKeyUpdate, 
                                    uint32_t keyUpdateTime, uint64_t keyUpdateTraffic);
```

##### 参数说明

| 参数名              | 参数类型 | 是否必选 | 描述                                                                    |
|------------------|------|------|-----------------------------------------------------------------------|
| ctx              | [IN] | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                                |
| isNeedKeyUpdate  | [IN] | 是    | 是否启用密钥更新<br/><code>true</code> 启用<br/><code>false</code>: 不启用         |
| keyUpdateTime    | [IN] | 是    | 达到此间隔时间后，更新密钥。范围 [1, 31536000]，单位 秒。                                  |
| keyUpdateTraffic | [IN] | 是    | 达到此流量后，更新密钥。范围 [1000, uint64_max]单位 byte，建议实际使用场景不低于1000000byte(1GB)。 |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.4.2 SCF_GetKeyAutoUpdateParam

##### 函数定义

获取密钥更新的流量和时间阈值。用于用户自定义校验内容。

##### 实现方法

```c++
int32_t SCF_GetKeyAutoUpdateParam(SCF_PolicyCtx *ctx, bool &isNeedKeyUpdate, 
                                    uint32_t &keyUpdateTime, uint64_t &keyUpdateTraffic);

```

##### 参数说明

| 参数名              | 参数类型  | 是否必选 | 描述                                                                                               |
|------------------|-------|------|--------------------------------------------------------------------------------------------------|
| ctx              | [IN]  | 是    | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)                                                           |
| isNeedKeyUpdate  | [OUT] | 是    | 是否启用密钥更新<br/><code>true</code> 启用<br/><code>false</code>: 不启用                                    |
| keyUpdateTime    | [OUT] | 是    | 达到此间隔时间后，更新密钥。范围 [1, 31536000]，单位 秒。<br/><code>isNeedKeyUpdate</code>为<code>true</code>时有效。      |
| keyUpdateTraffic | [OUT] | 是    | 达到此流量后，更新密钥。范围 [1000, uint64_max]单位 byte。<br/><code>isNeedKeyUpdate</code>为<code>true</code>时有效。 |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.4.3 SCF_ObjKeyUpdate

##### 函数定义

主动触发当前链路的会话密钥更新。

##### 实现方法

```c++
int32_t SCF_ObjKeyUpdate(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名  | 参数类型 | 是否必选 | 描述                                    |
|------|------|------|---------------------------------------|
| func | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.4.4 SCF_GetKeyUpdateInfo

##### 函数定义

获取当前会话密钥更新信息。

##### 实现方法

```c++
int32_t SCF_GetKeyUpdateInfo(SCF_PolicyObj *obj, uint64_t *lastKeyUpdateTime,
                               uint32_t *timeInterval, uint64_t *remainTraffic);
```

##### 参数说明

| 参数名               | 参数类型 | 是否必选 | 描述                                    |
|-------------------|------|------|---------------------------------------|
| obj               | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |
| lastKeyUpdateTime | [IN] | 是    | 上次主动更新密钥时间                            |
| timeInterval      | [IN] | 是    | 更新时间周期                                |
| remainTraffic     | [IN] | 是    | 距离下次主动更新密钥的剩余写流量                      |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

### 2.5 安全通信模块

#### 2.5.1 SCF_SetFd

##### 函数定义

配置安全通信的使用的socket。

##### 实现方法

```c++
int32_t SCF_SetFd(SCF_PolicyObj *obj, int32_t fd);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |
| fd  | [IN] | 是    | socket id                             |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.5.2 SCF_Connect

##### 函数定义

客户端向服务端发起连接。数据传输完成后调用[SCF_Close](#254-SCF_Close)关闭连接。

##### 实现方法

```c++
int32_t SCF_Connect(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.5.3 SCF_Accept

##### 函数定义

服务端等待客户端连接。数据传输完成后调用[SCF_Close](#254-SCF_Close)关闭连接。

##### 实现方法

```c++
int32_t SCF_Accept(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)

#### 2.5.4 SCF_Close

##### 函数定义

关闭安全通信。

##### 实现方法

```c++
int32_t SCF_Close(SCF_PolicyObj *obj);
```

##### 参数说明

| 参数名 | 参数类型 | 是否必选 | 描述                                    |
|-----|------|------|---------------------------------------|
| obj | [IN] | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)<br>
<code>obj</code>传<code>nullptr</code> 视为已经关闭，返回的是成功

#### 2.5.5 SCF_Read

##### 函数定义

读取传输数据。

##### 实现方法

```c++
int32_t SCF_Read(SCF_PolicyObj *obj, uint8_t *data, uint32_t dataLen, uint32_t *readLen);
```

##### 参数说明

| 参数名     | 参数类型     | 是否必选 | 描述                                    |
|---------|----------|------|---------------------------------------|
| obj     | [IN]     | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |
| data    | [IN/OUT] | 是    | 读取的数据buffer                           |
| dataLen | [IN]     | 是    | data 的大小。                             |
| readLen | [OUT]    | 是    | 实际读取长度                                |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)
<br/><code>SCF_SSL_ERR_WANT_READ</code>为合理错误场景，可以继续读取。

#### 2.5.6 SCF_Write

##### 函数定义

写入传输数据。

##### 实现方法

```c++
int32_t SCF_Write(SCF_PolicyObj *obj, const uint8_t *data, uint32_t dataLen, uint32_t *writeLen);
```

##### 参数说明

| 参数名      | 参数类型  | 是否必选 | 描述                                    |
|----------|-------|------|---------------------------------------|
| obj      | [IN]  | 是    | 安全策略对象实例，见[1.2.3 安全策略对象](#123-安全策略对象) |
| data     | [IN]  | 是    | 写入数据buffer                            |
| dataLen  | [IN]  | 是    | data 的大小。                             |
| writeLen | [OUT] | 是    | 实际写入长度                                |

##### 返回值

错误码，见[1.4 错误码](#14-错误码)
<br/><code>SCF_SSL_ERR_WANT_WRITE</code>为合理错误场景，可以继续写入。

### 2.6 RBAC 节点身份与角色

本节接口用于从证书扩展或运行期映射表解析节点身份和 RBAC 角色。`MAX_NODE_ID_LEN` 的值为
128，其中包含结尾空字符，因此节点 ID 的有效长度为 1～127 字节。该长度是 SCF API 的约束，不是
X.509 标准限制；角色映射仅保存在当前进程的策略上下文中。
NodeId 扩展的 OID 固定为 `1.3.6.1.4.1.2011.999.1`，Role 扩展的 OID 固定为
`1.3.6.1.4.1.2011.999.2`。两者的 `extnValue` 都必须是一个 DER 编码的 `UTF8String`，而不是裸文本。
当前实现不以 `critical` 标志作为解析条件；由于默认 OpenSSL 验证器未注册这两个自定义 OID，
为避免未知 critical 扩展导致链校验失败，配置时应保持非 critical（不要写 `critical,`）。只有在验证器已注册并处理这两个 OID
时，才可按其策略设置 critical，且仍必须保留 DER `UTF8String` 编码。

扩展值可以使用 UTF-8 明文配置，OpenSSL 会将 `ASN1:UTF8String:` 后的文本编码为 DER
UTF8String，无需手工转换为十六进制。以下完整命令会生成 RSA 私钥 `node.key` 和包含 NodeId、Role
扩展请求的 CSR `node.csr`：

```bash
openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -keyout node.key -out node.csr -subj "/CN=node-cert" \
    -addext "1.3.6.1.4.1.2011.999.1=ASN1:UTF8String:node-cert" \
    -addext "1.3.6.1.4.1.2011.999.2=ASN1:UTF8String:master"
```

以下命令生成带口令私钥的 CSR、使用 CA 签发证书并查看结果。口令由 OpenSSL 交互式读取，不要在命令行中
填写明文口令；签发前需确认 CSR 中的 NodeId、Role 与可信登记信息一致：

```bash
# 生成带口令的 CA 私钥和自签名 CA 证书
openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 \
    -keyout ca.key -out ca.cert -subj "/CN=Test CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
# 生成带口令的节点私钥和包含 NodeId、Role 的 CSR
openssl req -new -newkey rsa:3072 -sha256 \
    -keyout node-protected.key -out node-protected.csr -subj "/CN=node-cert" \
    -addext "1.3.6.1.4.1.2011.999.1=ASN1:UTF8String:node-cert" \
    -addext "1.3.6.1.4.1.2011.999.2=ASN1:UTF8String:master"
# 验证并查看 CSR
openssl req -in node-protected.csr -noout -verify -text
# 生成受控的节点证书扩展文件
printf '%s\n' 'basicConstraints=critical,CA:false' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=clientAuth,serverAuth' \
    '1.3.6.1.4.1.2011.999.1=ASN1:UTF8String:node-cert' \
    '1.3.6.1.4.1.2011.999.2=ASN1:UTF8String:master' > node.ext
# 使用 CA 签发节点证书
openssl x509 -req -in node-protected.csr -CA ca.cert -CAkey ca.key \
    -CAcreateserial -days 365 -sha256 -extfile node.ext -out node.crt
# 查看签发后的节点证书
openssl x509 -in node.crt -noout -text
```

#### 2.6.1 SCF_GetCertNodeId

##### 函数定义

```c++
int32_t SCF_GetCertNodeId(const void *cert, char *nodeIdBuffer, size_t bufferLen, size_t *nodeIdLen);
```

从证书的 NodeId 自定义扩展读取节点 ID。

证书必须包含唯一的 NodeId 扩展，扩展值必须是规范 DER 编码的 UTF8String；解码后必须是合法 UTF-8，
长度为 1～127 字节且不含嵌入的空字符。本接口只解析扩展，不单独验证证书链、签名或有效期。

| 参数名 | 参数类型 | 是否必选 | 描述 |
|---|---|---|---|
| cert | [IN] | 是 | 证书句柄，通过[SCF_GetCurrentCert](#228-SCF_GetCurrentCert)或[SCF_GetPeerCert](#229-SCF_GetPeerCert)获取，使用完成后通过[SCF_FreeCert](#2210-SCF_FreeCert)释放。 |
| nodeIdBuffer | [OUT] | 是 | 节点 ID 输出缓冲区，长度至少为 2，且必须大于节点 ID 的字节长度以容纳结尾空字符。 |
| bufferLen | [IN] | 是 | 输出缓冲区长度。 |
| nodeIdLen | [OUT] | 是 | 节点 ID 实际长度，不包含结尾空字符。 |

##### 返回值

成功返回 `SCF_SUCCESS`；证书不含 NodeId 扩展时返回 `SCF_ERRNO_CERT_NODE_ID_ABSENT`；扩展编码或缓冲区不合法时返回相应错误码。

#### 2.6.2 SCF_GetCertRbacRole

##### 函数定义

```c++
int32_t SCF_GetCertRbacRole(const void *cert, SCF_RBAC_ROLE *role);
```

从证书的 RBAC 角色自定义扩展读取角色。扩展值 `master` 和 `slave` 不区分大小写。

证书必须包含唯一的 Role 扩展，扩展值必须是规范 DER 编码的 UTF8String，解码后只能为 `master`
或 `slave`。本接口只解析扩展，不单独验证证书链、签名或有效期。

| 参数名 | 参数类型 | 是否必选 | 描述 |
|---|---|---|---|
| cert | [IN] | 是 | 证书句柄，通过[SCF_GetCurrentCert](#228-SCF_GetCurrentCert)或[SCF_GetPeerCert](#229-SCF_GetPeerCert)获取，使用完成后通过[SCF_FreeCert](#2210-SCF_FreeCert)释放。 |
| role | [OUT] | 是 | 解析出的节点角色，见[1.1.15 RBAC 角色](#1115-rbac-角色)。 |

##### 返回值

成功返回 `SCF_SUCCESS`；角色扩展缺失时返回 `SCF_ERRNO_CERT_ROLE_EXT_ABSENT`；扩展值或编码非法时返回相应错误码。

#### 2.6.3 SCF_SetNodeRoleMapping

##### 函数定义

```c++
int32_t SCF_SetNodeRoleMapping(SCF_PolicyCtx *ctx, const char *nodeId, SCF_RBAC_ROLE role);
```

新增或覆盖当前策略上下文中的节点 ID 到角色映射。

单个策略上下文最多保存 4096 个不同节点 ID 的映射；在已达上限时仍可覆盖已有节点的角色。节点 ID
必须以空字符结尾，有效长度为 1～127 字节；角色只能为 `SCF_RBAC_ROLE_MASTER` 或
`SCF_RBAC_ROLE_SLAVE`。任一使用该上下文的连接成功建链后，映射表冻结，不再允许新增、覆盖或删除。

| 参数名 | 参数类型 | 是否必选 | 描述                                                                                        |
|---|---|---|-------------------------------------------------------------------------------------------|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。                                                   |
| nodeId | [IN] | 是 | 非空且以空字符结尾的节点 ID，不允许使用策略保留字 "*"，有效长度为 1～127 字节。                                            |
| role | [IN] | 是 | 节点角色，见[1.1.15 RBAC 角色](#1115-rbac-角色)；只允许 `SCF_RBAC_ROLE_MASTER` 或 `SCF_RBAC_ROLE_SLAVE`。 |

##### 返回值

成功返回 `SCF_SUCCESS`；新增映射时映射表已达到 4096 条则返回 `SCF_ERRNO_RBAC_MAP_FULL`；任一使用该上下文的连接建链成功后返回 `SCF_ERRNO_RBAC_MAP_FROZEN`；参数非法时返回相应错误码。

#### 2.6.4 SCF_RemoveNodeRoleMapping

##### 函数定义

```c++
int32_t SCF_RemoveNodeRoleMapping(SCF_PolicyCtx *ctx, const char *nodeId);
```

删除当前策略上下文中的指定节点角色映射。

节点 ID 必须以空字符结尾，有效长度为 1～127 字节，且必须存在于当前策略上下文的映射表中。任一使用该
上下文的连接成功建链后，映射表冻结，不再允许删除。

| 参数名 | 参数类型 | 是否必选 | 描述                                                |
|---|---|---|---------------------------------------------------|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。           |
| nodeId | [IN] | 是 | 待删除的节点 ID，必须以空字符结尾，不允许使用策略保留字 "*"，有效长度为 1～127 字节。 |

##### 返回值

成功返回 `SCF_SUCCESS`；映射不存在时返回 `SCF_ERRNO_RBAC_MAP_NOT_FOUND`；任一使用该上下文的连接建链成功后返回 `SCF_ERRNO_RBAC_MAP_FROZEN`；参数非法时返回相应错误码。

#### 2.6.5 SCF_GetNodeRbacRole

##### 函数定义

```c++
int32_t SCF_GetNodeRbacRole(SCF_PolicyCtx *ctx, const void *cert, const char *nodeId,
    SCF_RBAC_ROLE *role, SCF_RBAC_ROLE_SOURCE *src);
```

解析节点角色。传入证书时优先使用证书角色；证书没有角色扩展时，使用证书中的 NodeId 查询映射表。
证书同时缺少角色和 NodeId 扩展时，使用调用方传入的 `nodeId` 查询映射表；
未传入证书时，直接使用 `nodeId` 查询映射表。
传入证书时，证书句柄及其已存在的 Role、NodeId 扩展必须满足[2.6.1 SCF_GetCertNodeId](#261-SCF_GetCertNodeId)和
[2.6.2 SCF_GetCertRbacRole](#262-SCF_GetCertRbacRole)的规格约束；未传入证书时，`nodeId` 必须以空字符结尾且有效长度为
1～127 字节。映射查询只读，映射表冻结后仍可调用本接口。

| 参数名 | 参数类型 | 是否必选 | 描述                                                                                                                                                                  |
|---|---|---|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。                                                                                                                             |
| cert | [IN] | 否 | 可选证书句柄，通过[SCF_GetCurrentCert](#228-SCF_GetCurrentCert)或[SCF_GetPeerCert](#229-SCF_GetPeerCert)获取，使用完成后通过[SCF_FreeCert](#2210-SCF_FreeCert)释放；非空时优先使用证书中的角色和 NodeId。 |
| nodeId | [IN] | 条件必选 | `cert` 为空或者证书中没有角色和NodeId扩展时用于映射表查询，必须以空字符结尾且有效长度为 1～127 字节，不允许使用策略保留字 "*"；`cert` 非空且有角色或NodeId扩展时不会作为证书身份的替代。                                                      |
| role | [OUT] | 是 | 解析出的节点角色，见[1.1.15 RBAC 角色](#1115-rbac-角色)。                                                                                                                          |
| src | [OUT] | 是 | 角色来源，见[1.1.16 RBAC 角色来源](#1116-rbac-角色来源)。                                                                                                                          |

##### 返回值

成功返回 `SCF_SUCCESS`；无法通过证书扩展或节点映射解析出角色时返回 `SCF_ERRNO_RBAC_ROLE_UNKNOWN`；
证书扩展存在但编码或取值非法时返回相应错误码。

### 2.7 RBAC 管理与策略规则

本节接口管理 RBAC 开关、master 节点查询和自定义策略规则。开关使用原子变量更新，节点角色映射和
策略规则分别使用内部互斥锁保护；接口可由多个线程并发调用，但调用期间不得释放传入的
`SCF_PolicyCtx`。规则仅在当前策略上下文生命周期内有效，按添加顺序保存，规则 ID 在该上下文内
单调递增且不会复用。单个策略上下文最多保存 8192 条规则。

#### 2.7.1 SCF_EnableRbac

##### 函数定义

```c++
int32_t SCF_EnableRbac(SCF_PolicyCtx *ctx, bool enable);
```

启用或关闭当前策略上下文的 RBAC 鉴权。新建上下文默认关闭。

`ctx` 必须是已初始化 SCF 创建且尚未释放的安全策略上下文。开关以原子方式更新，并发调用不会产生
数据竞争；多个线程同时设置时，最终状态取决于原子写入顺序。

| 参数名 | 参数类型 | 是否必选 | 描述 |
|---|---|---|---|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。 |
| enable | [IN] | 是 | `true` 启用 RBAC，`false` 关闭 RBAC。 |

##### 返回值

成功返回 `SCF_SUCCESS`；`ctx` 为空时返回 `SCF_ERRNO_NULL_INPUT`；SCF 未初始化时返回
`SCF_ERRNO_NOT_INIT`。

#### 2.7.2 SCF_ListMasterNodes

##### 函数定义

```c++
int32_t SCF_ListMasterNodes(SCF_PolicyCtx *ctx, char nodeIdList[][MAX_NODE_ID_LEN],
    uint32_t listCap, uint32_t *actualCount);
```

获取节点角色映射表中 master 节点的快照。

`nodeIdList` 必须至少包含 `listCap` 个元素，每个元素均为 `MAX_NODE_ID_LEN` 字节。`listCap` 必须
大于 0；输出容量不足时截断，不视为错误，节点返回顺序不作保证。每个返回的节点 ID 均以空字符结尾，
有效长度为 1～127 字节。接口持有映射表锁完成复制，返回内容不会混合并发修改前后的状态。

| 参数名 | 参数类型 | 是否必选 | 描述 |
|---|---|---|---|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。 |
| nodeIdList | [OUT] | 是 | master 节点 ID 输出数组，每个元素的大小必须为 `MAX_NODE_ID_LEN`。 |
| listCap | [IN] | 是 | `nodeIdList` 的元素数量，必须大于 0。 |
| actualCount | [OUT] | 是 | 实际写入的节点数量，最大为 `listCap`。 |

##### 返回值

成功（包括因容量不足而截断）返回 `SCF_SUCCESS`；任一指针参数为空时返回
`SCF_ERRNO_NULL_INPUT`；`listCap` 为 0 时返回 `SCF_ERRNO_INVALID_PARAM`；SCF 未初始化或复制失败时
返回相应错误码。

#### 2.7.3 SCF_IsMasterNode

##### 函数定义

```c++
int32_t SCF_IsMasterNode(SCF_PolicyCtx *ctx, const char *nodeId, bool *isMaster);
```

查询映射表中指定节点的角色是否为 master。

`nodeId` 必须以空字符结尾，有效长度为 1～127 字节，并且必须存在于当前策略上下文的节点角色映射
中。映射角色为 master 时输出 `true`，为 slave 时输出 `false`。接口在查询映射前将 `isMaster`
初始化为 `false`，因此映射不存在时返回 `SCF_ERRNO_RBAC_MAP_NOT_FOUND`，同时输出保持为 `false`；
调用方应通过返回码区分 slave 与映射不存在。

| 参数名 | 参数类型 | 是否必选 | 描述                                                |
|---|---|---|---------------------------------------------------|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。           |
| nodeId | [IN] | 是 | 待查询的节点 ID，必须以空字符结尾，不允许使用策略保留字 "*"，有效长度为 1～127 字节。 |
| isMaster | [OUT] | 是 | 查询结果；master 为 `true`，slave 或映射不存在为 `false`。       |

##### 返回值

映射存在并成功查询时返回 `SCF_SUCCESS`；映射不存在时返回 `SCF_ERRNO_RBAC_MAP_NOT_FOUND`；指针
参数为空时返回 `SCF_ERRNO_NULL_INPUT`；节点 ID 非法时返回 `SCF_ERRNO_INVALID_PARAM`；SCF 未初始化
时返回 `SCF_ERRNO_NOT_INIT`。

#### 2.7.4 SCF_AddPolicyRule

##### 函数定义

```c++
int32_t SCF_AddPolicyRule(SCF_PolicyCtx *ctx, const char *subjectNodeId, const char *targetNodeId,
    uint32_t resourceTypeBitmap, uint32_t actionBitmap, SCF_POLICY_EFFECT effect, uint32_t *ruleId);
```

添加自定义策略规则。

主体节点和目标节点必须以空字符结尾，精确节点 ID 的有效长度为 1～127 字节。主体节点必须为精确
节点 ID，不允许使用通配符；目标节点可以为精确节点 ID 或 `"*"`。资源类型位图必须是
`SCF_RES_TYPE_FD`、`SCF_RES_TYPE_NUMA`、`SCF_RES_TYPE_ADDR` 的非零组合；动作位图必须是
`SCF_RES_ACTION_APPLY`、`SCF_RES_ACTION_RELEASE` 的非零组合。规则效果只能为 allow 或 deny。

主体、目标、资源类型位图和动作位图共同构成规则匹配键。同一匹配键只能配置一条规则：规则效果相同
视为重复，规则效果不同时视为冲突，两种情况均返回 `SCF_ERRNO_RBAC_POLICY_DUPLICATE`。框架分配的
`ruleId` 不参与匹配键判断。单个策略上下文最多保存 8192 条规则；添加成功后 `ruleId` 在该上下文内
唯一且不复用。

| 参数名 | 参数类型 | 是否必选 | 描述                                                                                                     |
|---|---|---|--------------------------------------------------------------------------------------------------------|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。                                                                |
| subjectNodeId | [IN] | 是 | 发起操作的精确节点 ID，不支持通配符，有效长度为 1～127 字节。                                                                    |
| targetNodeId | [IN] | 是 | 目标节点 ID（有效长度为 1～127 字节）或通配符 `"*"`。                                                                     |
| resourceTypeBitmap | [IN] | 是 | 非零资源类型位图，取值见[1.1.18 RBAC 资源类型](#1118-rbac-资源类型)。                                                       |
| actionBitmap | [IN] | 是 | 非零资源操作位图，取值见[1.1.17 RBAC 资源操作](#1117-rbac-资源操作)，仅允许 SCF_RES_ACTION_APPLY 和 SCF_RES_ACTION_RELEASE 的组合。 |
| effect | [IN] | 是 | 规则效果，见[1.1.19 RBAC 策略效果](#1119-rbac-策略效果)，仅允许 SCF_POLICY_EFFECT_ALLOW 或 SCF_POLICY_EFFECT_DENY。                                                            |
| ruleId | [OUT] | 是 | 新增规则的唯一 ID，仅在成功时写入。                                                                                    |

##### 返回值

成功返回 `SCF_SUCCESS`；规则参数非法时返回 `SCF_ERRNO_RBAC_POLICY_INVALID`；规则重复或效果冲突时
返回 `SCF_ERRNO_RBAC_POLICY_DUPLICATE`；规则数量达到 8192 或规则 ID 耗尽时返回
`SCF_ERRNO_RBAC_POLICY_FULL`；内存分配失败时返回 `SCF_ERRNO_MEM_ALLOC`；任一指针参数为空或 SCF 未
初始化时返回相应错误码。

#### 2.7.5 SCF_RemovePolicyRule

##### 函数定义

```c++
int32_t SCF_RemovePolicyRule(SCF_PolicyCtx *ctx, uint32_t ruleId);
```

按规则 ID 删除当前策略上下文中的自定义策略规则。`ruleId` 必须大于 0 且对应一条现有规则；删除后
该 ID 不会再次分配。

| 参数名 | 参数类型 | 是否必选 | 描述 |
|---|---|---|---|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。 |
| ruleId | [IN] | 是 | 由[SCF_AddPolicyRule](#274-SCF_AddPolicyRule)返回且大于 0 的规则 ID。 |

##### 返回值

成功返回 `SCF_SUCCESS`；规则不存在时返回 `SCF_ERRNO_RBAC_POLICY_NOT_FOUND`；`ruleId` 为 0 时返回
`SCF_ERRNO_INVALID_PARAM`；`ctx` 为空或 SCF 未初始化时返回相应错误码。

#### 2.7.6 SCF_ListPolicyRules

##### 函数定义

```c++
int32_t SCF_ListPolicyRules(SCF_PolicyCtx *ctx, SCF_PolicyRule *rules,
    uint32_t ruleCap, uint32_t *actualCount);
```

按添加顺序获取自定义策略规则快照。

`rules` 必须指向至少包含 `ruleCap` 个已构造 `SCF_PolicyRule` 对象的数组，`ruleCap` 必须大于 0。
输出容量不足时截断，不视为错误；`actualCount` 表示实际写入数量而非规则总数。接口持有规则锁完成
复制，返回内容不会混合并发增删前后的状态。复制时若内存分配失败，接口返回
`SCF_ERRNO_MEM_ALLOC`，`actualCount` 保留已完整写入的规则数，`rules[0..actualCount)` 有效，其余元素
保持调用前状态。规则结构见[1.2.5 RBAC 策略规则](#125-rbac-策略规则)。

| 参数名 | 参数类型 | 是否必选 | 描述 |
|---|---|---|---|
| ctx | [IN] | 是 | 安全策略上下文，见[1.2.2 安全策略上下文](#122-安全策略上下文)。 |
| rules | [OUT] | 是 | 规则输出数组，元素类型见[1.2.5 RBAC 策略规则](#125-rbac-策略规则)。 |
| ruleCap | [IN] | 是 | `rules` 的元素数量，必须大于 0。 |
| actualCount | [OUT] | 是 | 已完整写入的规则数量，最大为 `ruleCap`；内存分配失败时保留已完成数量。 |

##### 返回值

成功（包括因容量不足而截断）返回 `SCF_SUCCESS`；任一指针参数为空时返回
`SCF_ERRNO_NULL_INPUT`；`ruleCap` 为 0 时返回 `SCF_ERRNO_INVALID_PARAM`；SCF 未初始化时返回
`SCF_ERRNO_NOT_INIT`；复制规则时内存分配失败返回 `SCF_ERRNO_MEM_ALLOC`。

### 2.8 RBAC 资源权限校验

本节接口用于校验本端操作节点对目标节点资源的申请或释放权限。接口根据自定义策略规则和节点角色
执行鉴权，不负责校验证书的合法性与可信链。

#### 2.8.1 SCF_CheckResourcePermission

##### 函数定义

```c++
int32_t SCF_CheckResourcePermission(SCF_PolicyCtx *ctx, const void *localCert,
    const char *targetNodeId, uint32_t resourceType, SCF_RESOURCE_ACTION action);
```

校验本端操作节点对目标节点资源的申请或释放权限。接口先匹配自定义策略规则；规则未命中时，master
默认允许任意节点资源操作，slave 默认仅允许本节点操作，未知角色拒绝访问。

`resourceType` 只接受 `SCF_RES_TYPE_FD`、`SCF_RES_TYPE_NUMA` 或 `SCF_RES_TYPE_ADDR`，不支持
`SCF_RES_TYPE_ALL` 或组合位图。`action` 只接受 `SCF_RES_ACTION_APPLY` 或
`SCF_RES_ACTION_RELEASE`，不支持组合动作。

本接口只执行 RBAC 鉴权，`localCert` 的合法性与可信链校验由调用方保证。自定义规则优先于默认规则；
在匹配的自定义规则中，主体、目标、资源类型和动作越精确者优先，同一优先级下 `DENY` 优先于
`ALLOW`。规则更新会立即影响后续调用，单次调用在一致的规则快照下完成裁决。

| 参数名 | 参数类型 | 是否必选 | 描述                        |
|---|---|---|---------------------------|
| ctx | [IN] | 是 | 已创建且已启用 RBAC 的安全策略上下文。    |
| localCert | [IN] | 是 | 本端操作节点证书，用于解析 NodeId 与角色。 |
| targetNodeId | [IN] | 是 | 目标资源所属的非空节点 ID，不允许使用策略保留字 "*"。          |
| resourceType | [IN] | 是 | 单个资源类型。                   |
| action | [IN] | 是 | 单个资源动作。                   |

##### 返回值

权限校验通过时返回 `SCF_SUCCESS`；当前策略上下文未启用 RBAC 时返回 `SCF_ERRNO_RBAC_DISABLED`；命中
拒绝规则或 slave 请求跨节点资源时返回 `SCF_ERRNO_RBAC_DENIED`；无法解析本端节点角色时返回
`SCF_ERRNO_RBAC_ROLE_UNKNOWN`；证书缺少 NodeId 扩展时返回 `SCF_ERRNO_CERT_NODE_ID_ABSENT`；证书扩展
解析失败、输入参数非法或框架未初始化时返回相应错误码。

### 2.9 安全连接接口

本节接口声明于 `scf_connection.h`，位于 `scf` 命名空间，仅供 C++ 调用。`SCFConnection` 封装策略上下文、
TLS 对象、传输对象和密码引擎的生命周期。

#### 2.9.1 SCFConnection

##### 创建与释放

```c++
class SCFConnection {
public:
    static SCFConnection *Create(const SCFConnectionConfig &config);
    virtual ~SCFConnection() = default;

protected:
    SCFConnection() = default;
};
```

当前 `Create` 实现直接使用 `new` 返回连接实例，内存分配失败时可能抛出 `std::bad_alloc`，不会主动返回
`nullptr`。返回对象由调用方持有，应使用 `delete` 释放；析构时自动释放连接相关资源。配置字段和默认值见
[1.2.6 安全连接配置](#126-安全连接配置)。

##### 连接生命周期

```c++
virtual int32_t Connect(const std::string &host, uint16_t port) = 0;
virtual int32_t Listen(const std::string &host, uint16_t port) = 0;
virtual SCFConnection *Accept() = 0;
virtual int32_t HandshakeStep() = 0;
virtual int32_t Close() = 0;
```

| 接口 | 说明 |
|---|---|
| Connect | 客户端连接目标主机和端口；非阻塞模式下返回后可能需要继续调用 `HandshakeStep` |
| Listen | 服务端绑定并监听；`host` 为空时监听 `0.0.0.0` |
| Accept | 接受新连接；非阻塞模式下没有可用连接时返回 `nullptr`；成功返回的对象由调用方 `delete`。子连接可能借用监听连接的密码引擎，因此监听连接必须晚于其所有子连接释放，否则可能产生悬空引用 |
| HandshakeStep | 推进一次 TLS 握手；完成返回 `SCF_SUCCESS`，等待事件时返回 `SCF_SSL_ERR_WANT_READ` 或 `SCF_SSL_ERR_WANT_WRITE` |
| Close | 主动关闭安全连接，成功返回 `SCF_SUCCESS` |

##### 数据传输

```c++
virtual int32_t Read(uint8_t *data, uint32_t len, uint32_t *readLen) = 0;
virtual int32_t Write(const uint8_t *data, uint32_t len, uint32_t *writeLen) = 0;
```

`Read` 将实际读取长度写入 `readLen`，`Write` 将实际写入长度写入 `writeLen`。成功返回 `SCF_SUCCESS`；
非阻塞重试和其他失败返回[错误码](#14-错误码)。

##### 状态查询与高级操作

```c++
virtual SCF_CONNECTION_STATE GetState() const = 0;
virtual bool IsConnected() const = 0;
virtual const char *GetTLSVersion() const = 0;
virtual uint16_t GetCipherSuite() const = 0;
virtual void *GetPeerCertificate() = 0;
virtual void FreePeerCertificate(void *cert) = 0;
virtual ITransport *GetTransport() const = 0;
virtual int32_t GetNativeHandle() const = 0;
virtual int32_t TriggerKeyUpdate() = 0;
virtual void SetUserData(void *userData) = 0;
virtual void *GetUserData() const = 0;
```

| 接口 | 说明 |
|---|---|
| GetState | 返回[连接状态](#1122-连接状态) |
| IsConnected | 返回安全通道是否已建立 |
| GetTLSVersion | 返回本次协商的 TLS 版本字符串 |
| GetCipherSuite | 当前实现尚未接入协商结果查询，固定返回 `0` |
| GetPeerCertificate | 建链成功后获取对端证书；返回的底层证书指针必须交给 `FreePeerCertificate` 释放 |
| FreePeerCertificate | 释放 `GetPeerCertificate` 返回的证书 |
| GetTransport | 返回连接持有的底层传输对象，不转移所有权 |
| GetNativeHandle | 返回用于事件循环的底层原生句柄 |
| TriggerKeyUpdate | 主动触发 TLS 1.3 KeyUpdate，成功返回 `SCF_SUCCESS` |
| SetUserData / GetUserData | 设置或读取用户指针；框架不接管该指针指向对象的生命周期 |

#### 2.9.2 安全连接便捷函数

```c++
SCFConnection *SCF_NewClientConnection(
    SCF_SECURITY_LEVEL securityLevel,
    const std::string &caCertPath = "");

SCFConnection *SCF_NewServerConnection(
    SCF_SECURITY_LEVEL securityLevel,
    const std::string &certPath,
    const std::string &keyPath);

SCFConnection *SCF_NewPSKConnection(
    SCF_SECURITY_LEVEL securityLevel,
    SCF_ROLE role,
    const std::string &pskIdentity,
    const uint8_t *pskKey, size_t pskKeyLen);
```

| 接口 | 参数与行为 |
|---|---|
| SCF_NewClientConnection | 创建客户端连接；`caCertPath` 为空时不校验对端证书 |
| SCF_NewServerConnection | 使用指定服务端证书和私钥创建服务端连接 |
| SCF_NewPSKConnection | 创建保存指定角色、PSK 身份和密钥的连接对象；当前实现未注册 PSK 会话回调，不能完成实际 PSK 建链 |

成功时返回由调用方 `delete` 的 `SCFConnection`，失败时返回 `nullptr`。

#### 2.9.3 传输与密码引擎注册

```c++
bool SCF_RegisterTransportFactory(ITransportFactory *factory);
void SCF_UnregisterTransportFactory(TransportProtocol protocol);
bool SCF_RegisterCryptoEngineFactory(ICryptoEngineFactory *factory);
void SCF_UnregisterCryptoEngineFactory(const std::string &name);
```

| 接口 | 说明 |
|---|---|
| SCF_RegisterTransportFactory | 按协议类型保存自定义传输工厂，成功返回 `true`，空指针返回 `false` |
| SCF_UnregisterTransportFactory | 按协议类型注销传输工厂 |
| SCF_RegisterCryptoEngineFactory | 按名称保存自定义密码引擎工厂，成功返回 `true`，空指针返回 `false` |
| SCF_UnregisterCryptoEngineFactory | 按工厂名称注销密码引擎工厂 |

当前注册表仅保存工厂的原始指针，不释放工厂对象，也不会自动把已注册工厂选入连接配置。调用方必须保证
注册期间工厂有效；创建连接时仍需将工厂显式赋给 `SCFConnectionConfig::transportFactory` 或
`SCFConnectionConfig::cryptoEngineFactory`。

### 2.10 密码引擎接口

本节接口声明于 `scf_crypto_engine.h`，位于 `scf` 命名空间。自定义软件引擎、密码卡或 Provider 引擎应实现
`ICryptoEngine`，并通过工厂注入高层连接。

#### 2.10.1 ICryptoEngine

##### 生命周期与能力

```c++
virtual ~ICryptoEngine() = default;
virtual bool Initialize(const CryptoEngineConfig &config) = 0;
virtual void Finalize() = 0;
virtual CryptoEngineCapability GetCapability() const = 0;
virtual bool IsInitialized() const = 0;
```

`Initialize` 成功返回 `true`；`Finalize` 释放引擎资源。`GetCapability` 返回的字段见
[1.2.7 密码引擎能力](#127-密码引擎能力)。

##### 密码运算

```c++
virtual bool EncryptAEAD(
    SymmetricAlgorithm algo,
    const uint8_t *key, size_t keyLen,
    const uint8_t *iv, size_t ivLen,
    const uint8_t *plaintext, size_t plaintextLen,
    const uint8_t *aad, size_t aadLen,
    uint8_t *ciphertext, size_t *ciphertextLen,
    uint8_t *tag, size_t tagLen) = 0;

virtual bool DecryptAEAD(
    SymmetricAlgorithm algo,
    const uint8_t *key, size_t keyLen,
    const uint8_t *iv, size_t ivLen,
    const uint8_t *ciphertext, size_t ciphertextLen,
    const uint8_t *aad, size_t aadLen,
    const uint8_t *tag, size_t tagLen,
    uint8_t *plaintext, size_t *plaintextLen) = 0;

virtual bool ECDHKeyAgreement(
    AsymmetricAlgorithm algo,
    const uint8_t *peerPublicKey, size_t peerPublicKeyLen,
    uint8_t *sharedSecret, size_t *sharedSecretLen) = 0;

virtual bool Sign(
    AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
    const uint8_t *digest, size_t digestLen,
    uint8_t *signature, size_t *sigLen) = 0;

virtual bool Verify(
    AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
    const uint8_t *digest, size_t digestLen,
    const uint8_t *signature, size_t sigLen) = 0;

virtual bool Hash(
    HashAlgorithm algo, const uint8_t *data, size_t dataLen,
    uint8_t *digest, size_t *digestLen) = 0;

virtual bool HMAC(
    HashAlgorithm algo, const uint8_t *key, size_t keyLen,
    const uint8_t *data, size_t dataLen,
    uint8_t *mac, size_t *macLen) = 0;

virtual bool HKDFExtract(
    HashAlgorithm algo, const uint8_t *salt, size_t saltLen,
    const uint8_t *ikm, size_t ikmLen,
    uint8_t *prk, size_t *prkLen) = 0;

virtual bool HKDFExpand(
    HashAlgorithm algo, const uint8_t *prk, size_t prkLen,
    const uint8_t *info, size_t infoLen,
    uint8_t *okm, size_t okmLen) = 0;

virtual bool RandomBytes(uint8_t *buffer, size_t len) = 0;
```

所有运算成功时返回 `true`，失败时返回 `false`。各输出长度通过相应长度指针返回；`aad` 可为 `nullptr`。
`DecryptAEAD` 仅在认证通过且解密成功时返回 `true`。

##### 密钥与 Provider 管理

```c++
virtual bool ImportKey(
    uint64_t keyId, const uint8_t *keyData, size_t keyDataLen,
    CryptoKeyHandle &handle) = 0;
virtual bool DestroyKey(const CryptoKeyHandle &handle) = 0;
virtual void *GetProviderContext() const = 0;
virtual bool IsHardwareAccelerated() const = 0;
virtual const char *GetAcceleratedAlgorithms() const = 0;
```

`ImportKey` 导入密钥；`keyData` 为 `nullptr` 时由硬件内部生成，并通过 `handle` 返回引用。
`GetProviderContext` 对 OpenSSL 3.0+ Provider 引擎返回 `OSSL_LIB_CTX *`，不使用 Provider 时返回 `nullptr`。
`GetAcceleratedAlgorithms` 返回用于日志展示的算法列表字符串。

#### 2.10.2 DefaultSoftwareCryptoEngine

`DefaultSoftwareCryptoEngine` 是基于 OpenSSL 的软件实现，但当前仅部分实现
[ICryptoEngine](#2101-ICryptoEngine)。

```c++
DefaultSoftwareCryptoEngine();
~DefaultSoftwareCryptoEngine() override;
```

它不是连接的自动回退引擎，`IsHardwareAccelerated()` 返回 `false`。当前 `Sign` 和 `Verify` 固定返回 `false`；
`ImportKey` 不解析或保存 `keyData`，仅填写句柄并返回 `true`；`DestroyKey` 不执行实际销毁操作。能力信息虽然列出
ECDSA，但当前不能通过该实现完成签名或验签，因此不应将其用于签名、验签或密钥托管。

#### 2.10.3 密码引擎工厂

```c++
class ICryptoEngineFactory {
public:
    virtual ~ICryptoEngineFactory() = default;
    virtual ICryptoEngine *Create() = 0;
    virtual const char *GetName() const = 0;
};

class DefaultSoftwareCryptoEngineFactory : public ICryptoEngineFactory {
public:
    ICryptoEngine *Create() override;
    const char *GetName() const override;
};
```

`Create` 返回新的引擎实例，`GetName` 返回工厂名称。自定义工厂可通过
[SCF_RegisterCryptoEngineFactory](#293-传输与密码引擎注册)注册；`DefaultSoftwareCryptoEngineFactory` 创建
默认软件引擎。

### 2.11 传输接口

本节接口声明于 `scf_transport.h`，位于 `scf` 命名空间。自定义 Socket、URMA 或其他传输后端应实现
`ITransport`，并通过 `ITransportFactory` 创建实例。

#### 2.11.1 TransportAddress 工厂方法

```c++
struct TransportAddress {
    static TransportAddress IPv4(const std::string &host, uint16_t port);
    static TransportAddress URMAAddr(const std::string &addr, uint16_t port = 0);
};
```

`IPv4` 返回类型为 `TransportAddressType::IPv4` 的地址；`URMAAddr` 返回类型为
`TransportAddressType::URMA` 的地址，端口默认值为 0。返回结构字段见
[1.2.10 传输端点地址](#1210-传输端点地址)。

#### 2.11.2 ITransport

```c++
virtual ~ITransport() = default;
virtual TransportProtocol GetProtocol() const = 0;
virtual TransportResult Connect(
    const TransportAddress &addr, const TransportConfig &config) = 0;
virtual TransportResult Bind(const TransportAddress &addr, int32_t backlog = 128) = 0;
virtual ITransport *Accept() = 0;
virtual TransportResult Send(const uint8_t *data, size_t len, size_t *sentLen) = 0;
virtual TransportResult Recv(uint8_t *data, size_t len, size_t *recvLen) = 0;
virtual void Close() = 0;
virtual int32_t GetNativeHandle() const = 0;
virtual bool IsConnected() const = 0;
virtual TransportAddress GetLocalAddress() const = 0;
virtual TransportAddress GetRemoteAddress() const = 0;
virtual TransportResult SetConfig(const TransportConfig &config) = 0;
virtual ITransport *Clone() const = 0;
```

| 接口 | 说明 |
|---|---|
| GetProtocol | 返回后端的[传输协议类型](#1129-传输协议类型) |
| Connect | 客户端按地址和配置发起连接 |
| Bind | 服务端绑定并监听，等待队列长度默认 128 |
| Accept | 接受连接并返回新的传输对象；调用方负责释放返回对象 |
| Send / Recv | 发送或接收数据，并通过 `sentLen` / `recvLen` 返回实际长度 |
| Close | 关闭传输连接 |
| GetNativeHandle | 返回平台相关原生句柄；不支持时返回 -1 |
| IsConnected | 返回连接是否有效 |
| GetLocalAddress / GetRemoteAddress | 返回本地或对端地址 |
| SetConfig | 更新传输配置 |
| Clone | 克隆传输对象，供 `Accept` 场景使用；调用方负责释放返回对象 |

除指针或布尔返回接口外，操作结果见[1.1.27 传输操作结果](#1127-传输操作结果)。

#### 2.11.3 ITransportFactory

```c++
class ITransportFactory {
public:
    virtual ~ITransportFactory() = default;
    virtual ITransport *Create() = 0;
    virtual TransportProtocol GetProtocol() const = 0;
    virtual const char *GetName() const = 0;
};
```

`Create` 返回新的传输对象，`GetProtocol` 返回工厂支持的协议类型，`GetName` 返回工厂名称。
自定义工厂可通过[SCF_RegisterTransportFactory](#293-传输与密码引擎注册)注册。
