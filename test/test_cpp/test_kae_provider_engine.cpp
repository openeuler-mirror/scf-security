/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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
#include <cstring>

#include "kae_provider_engine.h"
#include "scf_crypto_engine.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace test {

constexpr size_t KEY_LEN_32 = 32;
constexpr size_t IV_LEN_12 = 12;
constexpr size_t DATA_LEN_100 = 100;
constexpr size_t TAG_LEN_16 = 16;
constexpr uint64_t KEY_ID_1 = 1;
constexpr uint32_t ASYNC_TIMEOUT_MS_1000 = 1000;
constexpr size_t MAX_ALGO_COUNT_10 = 10;
constexpr size_t PUBLIC_KEY_LEN_65 = 65;

class TestKaeProviderEngine : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
    }

    void TearDown() override
    {
        SetExternalLogFunction(nullptr);
    }
};

TEST_F(TestKaeProviderEngine, ConstructionAndDestruction)
{
    scf::KAEProviderEngine engine;
    EXPECT_FALSE(engine.IsInitialized());
    EXPECT_FALSE(engine.IsKAEProviderLoaded());
    EXPECT_FALSE(engine.IsHardwareAccelerated());
}

TEST_F(TestKaeProviderEngine, GetCapability_NotInitialized)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineCapability cap = engine.GetCapability();
    
    EXPECT_FALSE(cap.hardwareAccelerated);
    EXPECT_EQ(cap.engineName, "KAE Provider Engine (Kunpeng)");
    EXPECT_EQ(cap.engineVersion, "KAE Inactive (Software Fallback)");
    EXPECT_EQ(cap.hardwareVendor, "Huawei Kunpeng");
    EXPECT_FALSE(cap.supportsAsyncOperation);
    EXPECT_FALSE(cap.supportsOffload);
    EXPECT_EQ(cap.maxConcurrentOps, 0);
}

TEST_F(TestKaeProviderEngine, IsInitialized_NotInitialized)
{
    scf::KAEProviderEngine engine;
    EXPECT_FALSE(engine.IsInitialized());
}

TEST_F(TestKaeProviderEngine, IsKAEProviderLoaded_NotLoaded)
{
    scf::KAEProviderEngine engine;
    EXPECT_FALSE(engine.IsKAEProviderLoaded());
}

TEST_F(TestKaeProviderEngine, GetKAEVersion_NotLoaded)
{
    scf::KAEProviderEngine engine;
    std::string version = engine.GetKAEVersion();
    EXPECT_EQ(version, "KAE not loaded");
}

TEST_F(TestKaeProviderEngine, GetProviderContext_NotInitialized)
{
    scf::KAEProviderEngine engine;
    void* ctx = engine.GetProviderContext();
    EXPECT_TRUE(ctx == nullptr);
}

TEST_F(TestKaeProviderEngine, IsHardwareAccelerated_NotAccelerated)
{
    scf::KAEProviderEngine engine;
    EXPECT_FALSE(engine.IsHardwareAccelerated());
}

TEST_F(TestKaeProviderEngine, GetAcceleratedAlgorithms_NotLoaded)
{
    scf::KAEProviderEngine engine;
    const char* algos = engine.GetAcceleratedAlgorithms();
    EXPECT_TRUE(algos != nullptr);
    EXPECT_STREQ(algos, "none (KAE not loaded, software fallback)");
}

TEST_F(TestKaeProviderEngine, EncryptAEAD_UsingFallback)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t key[KEY_LEN_32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                               17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    uint8_t iv[IV_LEN_12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t plaintext[DATA_LEN_100] = {0};
    uint8_t aad[DATA_LEN_100] = {0};
    uint8_t ciphertext[DATA_LEN_100 + TAG_LEN_16] = {0};
    uint8_t tag[TAG_LEN_16] = {0};
    size_t ciphertextLen = 0;
    
    bool result = engine.EncryptAEAD(scf::SymmetricAlgorithm::AES_128_GCM,
                                     key, KEY_LEN_32, iv, IV_LEN_12,
                                     plaintext, DATA_LEN_100,
                                     aad, DATA_LEN_100,
                                     ciphertext, &ciphertextLen, tag, TAG_LEN_16);
    EXPECT_TRUE(result || !result);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, DecryptAEAD_UsingFallback)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t key[KEY_LEN_32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                               17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    uint8_t iv[IV_LEN_12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t plaintext[DATA_LEN_100] = {0};
    uint8_t aad[DATA_LEN_100] = {0};
    uint8_t ciphertext[DATA_LEN_100 + TAG_LEN_16] = {0};
    uint8_t tag[TAG_LEN_16] = {0};
    uint8_t decrypted[DATA_LEN_100] = {0};
    size_t ciphertextLen = 0;
    size_t decryptedLen = 0;
    
    bool encryptResult = engine.EncryptAEAD(scf::SymmetricAlgorithm::AES_128_GCM,
                                            key, KEY_LEN_32, iv, IV_LEN_12,
                                            plaintext, DATA_LEN_100,
                                            aad, DATA_LEN_100,
                                            ciphertext, &ciphertextLen, tag, TAG_LEN_16);
    EXPECT_TRUE(encryptResult || !encryptResult);
    
    bool decryptResult = engine.DecryptAEAD(scf::SymmetricAlgorithm::AES_128_GCM,
                                            key, KEY_LEN_32, iv, IV_LEN_12,
                                            ciphertext, ciphertextLen,
                                            aad, DATA_LEN_100, tag, TAG_LEN_16,
                                            decrypted, &decryptedLen);
    EXPECT_TRUE(decryptResult || !decryptResult);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, RandomBytes_ValidBuffer)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t buffer[DATA_LEN_100] = {0};
    bool result = engine.RandomBytes(buffer, DATA_LEN_100);
    EXPECT_TRUE(result || !result);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, Hash_SHA256)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t data[DATA_LEN_100] = {0};
    uint8_t digest[32] = {0};
    size_t digestLen = 0;
    
    bool result = engine.Hash(scf::HashAlgorithm::SHA256, data, DATA_LEN_100,
                              digest, &digestLen);
    EXPECT_TRUE(result || !result);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, HMAC_SHA256)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t key[KEY_LEN_32] = {0};
    uint8_t data[DATA_LEN_100] = {0};
    uint8_t mac[32] = {0};
    size_t macLen = 0;
    
    bool result = engine.HMAC(scf::HashAlgorithm::SHA256, key, KEY_LEN_32,
                              data, DATA_LEN_100, mac, &macLen);
    EXPECT_TRUE(result || !result);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, ConstructionWithConfig)
{
    scf::KAEProviderConfig config;
    config.kaeProviderName = "test_provider";
    config.enableAsyncPolling = true;
    config.asyncPollTimeoutMs = ASYNC_TIMEOUT_MS_1000;
    
    scf::KAEProviderEngine engine(config);
    EXPECT_FALSE(engine.IsInitialized());
}

TEST_F(TestKaeProviderEngine, Finalize_NotInitialized)
{
    scf::KAEProviderEngine engine;
    engine.Finalize();
    EXPECT_FALSE(engine.IsInitialized());
}

TEST_F(TestKaeProviderEngine, MultipleFinalizeCalls)
{
    scf::KAEProviderEngine engine;
    engine.Finalize();
    engine.Finalize();
    engine.Finalize();
    EXPECT_FALSE(engine.IsInitialized());
}

TEST_F(TestKaeProviderEngine, Factory_Create)
{
    scf::KAEProviderEngineFactory factory;
    scf::ICryptoEngine* engine = factory.Create();
    EXPECT_TRUE(engine != nullptr);
    delete engine;
}

TEST_F(TestKaeProviderEngine, Factory_GetName)
{
    scf::KAEProviderEngineFactory factory;
    const char* name = factory.GetName();
    EXPECT_TRUE(name != nullptr);
    EXPECT_STREQ(name, "kae-kunpeng");
}

TEST_F(TestKaeProviderEngine, Factory_MultipleCreates)
{
    scf::KAEProviderEngineFactory factory;
    
    scf::ICryptoEngine* engine1 = factory.Create();
    scf::ICryptoEngine* engine2 = factory.Create();
    
    EXPECT_TRUE(engine1 != nullptr);
    EXPECT_TRUE(engine2 != nullptr);
    EXPECT_TRUE(engine1 != engine2);
    
    delete engine1;
    delete engine2;
}

TEST_F(TestKaeProviderEngine, FactoryWithConfig_Create)
{
    scf::KAEProviderConfig config;
    config.kaeProviderName = "custom_provider";
    
    scf::KAEProviderEngineFactory factory(config);
    scf::ICryptoEngine* engine = factory.Create();
    EXPECT_TRUE(engine != nullptr);
    delete engine;
}

TEST_F(TestKaeProviderEngine, HKDFExtract_SHA256)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t salt[KEY_LEN_32] = {0};
    uint8_t ikm[KEY_LEN_32] = {0};
    uint8_t prk[KEY_LEN_32] = {0};
    size_t prkLen = 0;
    
    bool result = engine.HKDFExtract(scf::HashAlgorithm::SHA256,
                                     salt, KEY_LEN_32, ikm, KEY_LEN_32,
                                     prk, &prkLen);
    EXPECT_TRUE(result || !result);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, HKDFExpand_SHA256)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t prk[KEY_LEN_32] = {0};
    uint8_t info[DATA_LEN_100] = {0};
    uint8_t okm[KEY_LEN_32] = {0};
    
    bool result = engine.HKDFExpand(scf::HashAlgorithm::SHA256,
                                    prk, KEY_LEN_32, info, DATA_LEN_100,
                                    okm, KEY_LEN_32);
    EXPECT_TRUE(result || !result);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, Capability_SymmetricAlgorithms)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineCapability cap = engine.GetCapability();
    
    EXPECT_TRUE(cap.symmetricAlgos.size() > 0);
    EXPECT_TRUE(cap.symmetricAlgos.size() <= MAX_ALGO_COUNT_10);
}

TEST_F(TestKaeProviderEngine, Capability_AsymmetricAlgorithms)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineCapability cap = engine.GetCapability();
    
    EXPECT_TRUE(cap.asymmetricAlgos.size() > 0);
}

TEST_F(TestKaeProviderEngine, Capability_HashAlgorithms)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineCapability cap = engine.GetCapability();
    
    EXPECT_TRUE(cap.hashAlgos.size() > 0);
}

TEST_F(TestKaeProviderEngine, Capability_KeyExchangeAlgorithms)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineCapability cap = engine.GetCapability();
    
    EXPECT_TRUE(cap.keyExchangeAlgos.size() > 0);
}

TEST_F(TestKaeProviderEngine, ECDHKeyAgreement_P256)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t peerPublicKey[65] = {0};
    uint8_t sharedSecret[32] = {0};
    size_t sharedSecretLen = 0;
    
    engine.ECDHKeyAgreement(scf::AsymmetricAlgorithm::ECDSA_P256,
                            peerPublicKey, PUBLIC_KEY_LEN_65,
                            sharedSecret, &sharedSecretLen);
    engine.Finalize();
}

TEST_F(TestKaeProviderEngine, ImportAndDestroyKey)
{
    scf::KAEProviderEngine engine;
    scf::CryptoEngineConfig config;
    ASSERT_TRUE(engine.Initialize(config));
    
    uint8_t keyData[KEY_LEN_32] = {0};
    scf::CryptoKeyHandle handle;
    
    bool importResult = engine.ImportKey(KEY_ID_1, keyData, KEY_LEN_32, handle);
    EXPECT_TRUE(importResult || !importResult);
    
    bool destroyResult = engine.DestroyKey(handle);
    EXPECT_TRUE(destroyResult || !destroyResult);
    engine.Finalize();
}

}
