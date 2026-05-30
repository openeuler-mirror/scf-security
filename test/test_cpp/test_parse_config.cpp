/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "parse_config.h"
#include "scf_inner.h"
#include "scf_errno.h"
#include "custom_logger.h"
#include "test_scf.h"
#include "scf.h"

namespace fs = std::filesystem;

namespace test {

class ParseConfigTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);

        testDir = GetLocalPath() + "/test/test_data/config_test";
        fs::create_directories(testDir);

        validConfigFile = testDir + "/valid_config.json";
        invalidJsonFile = testDir + "/invalid_json.json";
        missingFieldFile = testDir + "/missing_field.json";
        emptyFile = testDir + "/empty.json";

        CreateValidConfigFile();
        CreateInvalidJsonFile();
        CreateMissingFieldFile();
        CreateEmptyFile();
    }

    void TearDown() override
    {
        fs::remove_all(testDir);
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }

    void CreateValidConfigFile()
    {
        std::ofstream file(validConfigFile);
        file << R"({
            "tlsVersion": {
                "minVersion": "SSL_VERSION_TLS12",
                "maxVersion": "SSL_VERSION_TLS13",
                "forbidVersion": []
            },
            "tlsCipherSuites": ["SCF_SSL_AES_128_GCM_SHA256"],
            "certs": [],
            "privKey": {
                "storeBuf": "",
                "keyAuth": {
                    "storeBuf": "",
                    "isCipher": true
                }
            }
        })";
    }

    void CreateInvalidJsonFile()
    {
        std::ofstream file(invalidJsonFile);
        file << "{ invalid json content }";
    }

    void CreateMissingFieldFile()
    {
        std::ofstream file(missingFieldFile);
        file << R"({
            "tlsVersion": {
                "minVersion": "SSL_VERSION_TLS12"
            }
        })";
    }

    void CreateEmptyFile()
    {
        std::ofstream file(emptyFile);
        file << "{}";
    }

    std::string testDir;
    std::string validConfigFile;
    std::string invalidJsonFile;
    std::string missingFieldFile;
    std::string emptyFile;
};

TEST_F(ParseConfigTest, SCF_ParseConfig_ValidConfig)
{
    scf::Config cfg;
    int ret = scf::SCF_ParseConfig(validConfigFile, cfg);
    EXPECT_EQ(ret, SCF_ERROR);
}

TEST_F(ParseConfigTest, SCF_ParseConfig_FileNotExist)
{
    scf::Config cfg;
    int ret = scf::SCF_ParseConfig("/nonexistent/config.json", cfg);
    EXPECT_EQ(ret, SCF_ERROR);
}

TEST_F(ParseConfigTest, SCF_ParseConfig_InvalidJson)
{
    scf::Config cfg;
    int ret = scf::SCF_ParseConfig(invalidJsonFile, cfg);
    EXPECT_EQ(ret, SCF_ERROR);
}

TEST_F(ParseConfigTest, SCF_ParseConfig_EmptyJson)
{
    scf::Config cfg;
    int ret = scf::SCF_ParseConfig(emptyFile, cfg);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(cfg.tlsVersion.minVersion, 0);
    EXPECT_EQ(cfg.tlsVersion.maxVersion, 0);
}

TEST_F(ParseConfigTest, SetProtocolVersion4PolicyCtx_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    scf::TlsVersion tlsVersion;
    tlsVersion.minVersion = SCF_SSL_VERSION_TLS12;
    tlsVersion.maxVersion = SCF_SSL_VERSION_TLS13;

    int ret = scf::SetProtocolVersion4PolicyCtx(ctx, tlsVersion);
    EXPECT_EQ(ret, SCF_ERROR);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SetProtocolVersion4PolicyCtx_ZeroVersion)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    scf::TlsVersion tlsVersion;
    tlsVersion.minVersion = 0;
    tlsVersion.maxVersion = 0;

    int ret = scf::SetProtocolVersion4PolicyCtx(ctx, tlsVersion);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SetCipherSuites4PolicyCtx_Valid)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    std::vector<uint16_t> cipherSuites = {SCF_SSL_AES_128_GCM_SHA256};

    int ret = scf::SetCipherSuites4PolicyCtx(ctx, cipherSuites);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SetCipherSuites4PolicyCtx_Empty)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    std::vector<uint16_t> cipherSuites;

    int ret = scf::SetCipherSuites4PolicyCtx(ctx, cipherSuites);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SetCipherSuites4PolicyCtx_Multiple)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    std::vector<uint16_t> cipherSuites = {
        SCF_SSL_AES_128_GCM_SHA256,
        SCF_SSL_AES_256_GCM_SHA384,
        SCF_SSL_CHACHA20_POLY1305_SHA256
    };

    int ret = scf::SetCipherSuites4PolicyCtx(ctx, cipherSuites);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, AddCert2PolicyCtx_Empty)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    std::vector<scf::Cert> certs;

    int ret = scf::AddCert2PolicyCtx(ctx, certs);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SetPrivKeyAndPwd4Ctx_Empty)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    scf::PrivKey privKey;
    privKey.storeBuf = "";
    privKey.keyAuth.storeBuf.clear();

    int ret = scf::SetPrivKeyAndPwd4Ctx(ctx, privKey);
    EXPECT_EQ(ret, SCF_SUCCESS);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SetPrivKeyAndPwd4Ctx_EmptyStoreBufWithKeyAuth)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    scf::PrivKey privKey;
    privKey.storeBuf = "";
    privKey.keyAuth.storeBuf.push_back('t');
    privKey.keyAuth.storeBuf.push_back('e');
    privKey.keyAuth.storeBuf.push_back('s');
    privKey.keyAuth.storeBuf.push_back('t');

    int ret = scf::SetPrivKeyAndPwd4Ctx(ctx, privKey);
    EXPECT_EQ(ret, SCF_ERROR);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, Config_DefaultConstructor)
{
    scf::Config cfg;
    EXPECT_EQ(cfg.tlsVersion.minVersion, 0);
    EXPECT_EQ(cfg.tlsVersion.maxVersion, 0);
    EXPECT_TRUE(cfg.tlsCipherSuites.empty());
    EXPECT_TRUE(cfg.certs.empty());
    EXPECT_EQ(cfg.privKey.storeBuf, "");
    EXPECT_TRUE(cfg.privKey.keyAuth.isCipher);
}

TEST_F(ParseConfigTest, SCF_SetConfigFile_NullCtx)
{
    int ret = SCF_SetConfigFile(nullptr, validConfigFile.c_str());
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);
}

TEST_F(ParseConfigTest, SCF_SetConfigFile_NullPath)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    int ret = SCF_SetConfigFile(ctx, nullptr);
    EXPECT_EQ(ret, SCF_ERRNO_NULL_INPUT);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SCF_SetConfigFile_InvalidPath)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    int ret = SCF_SetConfigFile(ctx, "relative/path");
    EXPECT_EQ(ret, SCF_ERROR);

    SCF_FreePolicyCtx(&ctx);
}

TEST_F(ParseConfigTest, SCF_SetConfigFile_NonExistentFile)
{
    SCF_PolicyCtx *ctx = SCF_CreatePolicyCtx();
    SCF_SetPolicy(ctx, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH);

    int ret = SCF_SetConfigFile(ctx, "/nonexistent/config.json");
    EXPECT_EQ(ret, SCF_ERROR);

    SCF_FreePolicyCtx(&ctx);
}

}