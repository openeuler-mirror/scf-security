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
    - [1.2 结构体](#12-结构体)
        - [1.2.1 文件上下文](#121-文件上下文)
        - [1.2.2 安全策略上下文](#122-安全策略上下文)
        - [1.2.3 安全策略对象](#123-安全策略对象)
        - [1.2.4 安全会话对象](#124-安全会话对象)
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

## 1 数据结构

### 1.1 枚举

#### 1.1.1 初始化类型

##### 定义

```c++
#define SCF_INIT_FLAG_OPENSSL 1
```

##### 用途

在调用[SCF_Init](#214-SCF_Init)时指定初始化的底层TLS实现

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

在调用[SCF_Init](#214-SCF_Init)时指定初始化的底层TLS实现

##### 属性说明

| 名称                                                  | 值      | 含义                        |
|-----------------------------------------------------|--------|---------------------------|
| SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | 0xC02B | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | 0xC02C | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | 0xC02F | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | 0xC030 | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | 0xCCA8 | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | 0xCCA9 | 取值来源rfc8446，仅支持TLS1.2协议使用 |
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

配置文件中配置TLS协议的最小版本、最大版本、禁用版本

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

配置文件中配置TLS协议的最小版本、最大版本、禁用版本

##### 属性说明

| 名称                                                  | 值      | 含义                        |
|-----------------------------------------------------|--------|---------------------------|
| SCF_SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | 0xC02B | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | 0xC02C | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | 0xC02F | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | 0xC030 | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | 0xCCA8 | 取值来源rfc8446，仅支持TLS1.2协议使用 |
| SCF_SSL_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | 0xCCA9 | 取值来源rfc8446，仅支持TLS1.2协议使用 |
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

配置文件中配置TLS协议的最小版本、最大版本、禁用版本

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
const char *GetErrorMessage(int32_t errorCode)
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
int32_t SCF_SessionGetProtocolVersion(SCF_Session *sess, char **version, size_t &versionLen)
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