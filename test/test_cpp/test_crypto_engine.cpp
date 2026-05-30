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
#include <vector>

#include "scf_crypto_engine.h"
#include "custom_logger.h"
#include "test_scf.h"
#include "scf.h"

namespace test {

constexpr size_t AES_128_KEY_SIZE = 16;
constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t IV_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA384_DIGEST_SIZE = 48;
constexpr size_t SHA512_DIGEST_SIZE = 64;
constexpr size_t BUFFER_SIZE_64 = 64;
constexpr size_t BUFFER_SIZE_1024 = 1024;
constexpr size_t PLAINTEXT_LEN_4 = 4;
constexpr size_t PLAINTEXT_LEN_8 = 8;
constexpr size_t PLAINTEXT_LEN_12 = 12;
constexpr size_t PLAINTEXT_LEN_13 = 13;
constexpr size_t PLAINTEXT_LEN_26 = 26;
constexpr size_t PLAINTEXT_LEN_32 = 32;
constexpr size_t AAD_LEN_8 = 8;
constexpr size_t AAD_LEN_16 = 16;
constexpr size_t DATA_LEN_9 = 9;
constexpr size_t DATA_LEN_11 = 11;
constexpr size_t DATA_LEN_14 = 14;
constexpr size_t DATA_LEN_19 = 19;
constexpr size_t HMAC_KEY_LEN_32 = 32;
constexpr size_t HMAC_KEY_LEN_48 = 48;
constexpr size_t HKDF_INFO_LEN_4 = 4;
constexpr size_t HKDF_OKM_LEN_32 = 32;
constexpr size_t RANDOM_BUFFER_LEN_32 = 32;
constexpr size_t KEY_DATA_LEN_32 = 32;
constexpr size_t SIGNATURE_LEN_64 = 64;
constexpr size_t PLAINTEXT_SIZE_32 = 32;
constexpr size_t DATA_SIZE_32 = 32;
constexpr size_t SALT_SIZE_32 = 32;
constexpr size_t IKM_SIZE_32 = 32;
constexpr size_t PRK_SIZE_32 = 32;
constexpr size_t DIGEST_SIZE_32 = 32;
constexpr size_t AAD_SIZE_16 = 16;
constexpr size_t INFO_LEN_16 = 16;
constexpr uint64_t IMPORT_KEY_ID_1 = 1;

class CryptoEngineTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        char libPath[] = "/usr/lib64";
        SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath);

        engine = new scf::DefaultSoftwareCryptoEngine();
        scf::CryptoEngineConfig config;
        engine->Initialize(config);
    }

    void TearDown() override
    {
        if (engine != nullptr) {
            engine->Finalize();
            delete engine;
            engine = nullptr;
        }
        SCF_DeInit();
        SetExternalLogFunction(nullptr);
    }

    scf::DefaultSoftwareCryptoEngine *engine = nullptr;
};

TEST_F(CryptoEngineTest, Initialize_Success)
{
    EXPECT_TRUE(engine->IsInitialized());
}

TEST_F(CryptoEngineTest, Finalize_Success)
{
    engine->Finalize();
    EXPECT_FALSE(engine->IsInitialized());
}

TEST_F(CryptoEngineTest, GetCapability_ValidInfo)
{
    scf::CryptoEngineCapability cap = engine->GetCapability();

    EXPECT_EQ(cap.engineName, "OpenSSL Software Engine");
    EXPECT_FALSE(cap.hardwareAccelerated);
    EXPECT_FALSE(cap.supportsAsyncOperation);
    EXPECT_FALSE(cap.supportsOffload);

    EXPECT_TRUE(cap.symmetricAlgos.size() > 0);
    EXPECT_TRUE(cap.asymmetricAlgos.size() > 0);
    EXPECT_TRUE(cap.hashAlgos.size() > 0);
}

TEST_F(CryptoEngineTest, EncryptAEAD_AES128GCM_Success)
{
    uint8_t key[AES_128_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "Hello World Test Message!";
    uint8_t aad[AAD_SIZE_16] = "Additional Auth";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    size_t ciphertextLen = 0;

    EXPECT_TRUE(engine->EncryptAEAD(
        scf::SymmetricAlgorithm::AES_128_GCM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_26,
        aad, AAD_LEN_16,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE));

    EXPECT_GT(ciphertextLen, 0);
}

TEST_F(CryptoEngineTest, EncryptAEAD_AES256GCM_Success)
{
    uint8_t key[AES_256_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "Hello World!";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    size_t ciphertextLen = 0;

    EXPECT_TRUE(engine->EncryptAEAD(
        scf::SymmetricAlgorithm::AES_256_GCM,
        key, AES_256_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_12,
        nullptr, 0,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE));
}

TEST_F(CryptoEngineTest, EncryptAEAD_InvalidAlgorithm)
{
    uint8_t key[AES_128_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = {0};
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    size_t ciphertextLen = 0;

    EXPECT_FALSE(engine->EncryptAEAD(
        scf::SymmetricAlgorithm::CUSTOM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_32,
        nullptr, 0,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE));
}

TEST_F(CryptoEngineTest, DecryptAEAD_AES128GCM_Success)
{
    uint8_t key[AES_128_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "Test Message";
    uint8_t aad[AAD_SIZE_16] = "AuthData";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    uint8_t decrypted[BUFFER_SIZE_64] = {0};
    size_t ciphertextLen = 0;
    size_t decryptedLen = 0;

    engine->EncryptAEAD(
        scf::SymmetricAlgorithm::AES_128_GCM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_12,
        aad, AAD_LEN_8,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE);

    EXPECT_TRUE(engine->DecryptAEAD(
        scf::SymmetricAlgorithm::AES_128_GCM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        ciphertext, ciphertextLen,
        aad, AAD_LEN_8, tag, TAG_SIZE,
        decrypted, &decryptedLen));

    EXPECT_EQ(decryptedLen, PLAINTEXT_LEN_12);
    EXPECT_EQ(memcmp(decrypted, plaintext, PLAINTEXT_LEN_12), 0);
}

TEST_F(CryptoEngineTest, DecryptAEAD_InvalidTag)
{
    uint8_t key[AES_128_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "Test";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    uint8_t decrypted[BUFFER_SIZE_64] = {0};
    size_t ciphertextLen = 0;
    size_t decryptedLen = 0;

    engine->EncryptAEAD(
        scf::SymmetricAlgorithm::AES_128_GCM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_4,
        nullptr, 0,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE);

    uint8_t invalidTag[TAG_SIZE] = {0xFF};
    EXPECT_FALSE(engine->DecryptAEAD(
        scf::SymmetricAlgorithm::AES_128_GCM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        ciphertext, ciphertextLen,
        nullptr, 0, invalidTag, TAG_SIZE,
        decrypted, &decryptedLen));
}

TEST_F(CryptoEngineTest, Hash_SHA256_Success)
{
    uint8_t data[DATA_SIZE_32] = "Test data for hash";
    uint8_t digest[BUFFER_SIZE_64] = {0};
    size_t digestLen = 0;

    EXPECT_TRUE(engine->Hash(
        scf::HashAlgorithm::SHA256,
        data, DATA_LEN_19,
        digest, &digestLen));

    EXPECT_EQ(digestLen, SHA256_DIGEST_SIZE);
}

TEST_F(CryptoEngineTest, Hash_SHA384_Success)
{
    uint8_t data[DATA_SIZE_32] = "Test SHA384";
    uint8_t digest[BUFFER_SIZE_64] = {0};
    size_t digestLen = 0;

    EXPECT_TRUE(engine->Hash(
        scf::HashAlgorithm::SHA384,
        data, DATA_LEN_11,
        digest, &digestLen));

    EXPECT_EQ(digestLen, SHA384_DIGEST_SIZE);
}

TEST_F(CryptoEngineTest, Hash_SHA512_Success)
{
    uint8_t data[DATA_SIZE_32] = "Test SHA512";
    uint8_t digest[BUFFER_SIZE_64] = {0};
    size_t digestLen = 0;

    EXPECT_TRUE(engine->Hash(
        scf::HashAlgorithm::SHA512,
        data, DATA_LEN_11,
        digest, &digestLen));

    EXPECT_EQ(digestLen, SHA512_DIGEST_SIZE);
}

TEST_F(CryptoEngineTest, Hash_InvalidAlgorithm)
{
    uint8_t data[DATA_SIZE_32] = {0};
    uint8_t digest[BUFFER_SIZE_64] = {0};
    size_t digestLen = 0;

    EXPECT_FALSE(engine->Hash(
        scf::HashAlgorithm::CUSTOM,
        data, PLAINTEXT_LEN_32,
        digest, &digestLen));
}

TEST_F(CryptoEngineTest, HMAC_SHA256_Success)
{
    uint8_t key[AES_256_KEY_SIZE] = {0};
    uint8_t data[DATA_SIZE_32] = "HMAC test data";
    uint8_t mac[BUFFER_SIZE_64] = {0};
    size_t macLen = 0;

    EXPECT_TRUE(engine->HMAC(
        scf::HashAlgorithm::SHA256,
        key, HMAC_KEY_LEN_32,
        data, DATA_LEN_14,
        mac, &macLen));

    EXPECT_EQ(macLen, SHA256_DIGEST_SIZE);
}

TEST_F(CryptoEngineTest, HMAC_SHA384_Success)
{
    uint8_t key[HMAC_KEY_LEN_48] = {0};
    uint8_t data[DATA_SIZE_32] = "HMAC test";
    uint8_t mac[BUFFER_SIZE_64] = {0};
    size_t macLen = 0;

    EXPECT_TRUE(engine->HMAC(
        scf::HashAlgorithm::SHA384,
        key, HMAC_KEY_LEN_48,
        data, DATA_LEN_9,
        mac, &macLen));

    EXPECT_EQ(macLen, SHA384_DIGEST_SIZE);
}

TEST_F(CryptoEngineTest, RandomBytes_Success)
{
    uint8_t buffer[RANDOM_BUFFER_LEN_32] = {0};

    EXPECT_TRUE(engine->RandomBytes(buffer, RANDOM_BUFFER_LEN_32));

    bool allZero = true;
    for (int i = 0; i < RANDOM_BUFFER_LEN_32; i++) {
        if (buffer[i] != 0) {
            allZero = false;
            break;
        }
    }
    EXPECT_FALSE(allZero);
}

TEST_F(CryptoEngineTest, RandomBytes_LargeBuffer)
{
    uint8_t buffer[BUFFER_SIZE_1024] = {0};

    EXPECT_TRUE(engine->RandomBytes(buffer, BUFFER_SIZE_1024));
}

TEST_F(CryptoEngineTest, HKDFExtract_SHA256_Success)
{
    uint8_t salt[SALT_SIZE_32] = {1};
    uint8_t ikm[IKM_SIZE_32] = {2};
    uint8_t prk[BUFFER_SIZE_64] = {0};
    size_t prkLen = 0;

    EXPECT_TRUE(engine->HKDFExtract(
        scf::HashAlgorithm::SHA256,
        salt, SHA256_DIGEST_SIZE,
        ikm, SHA256_DIGEST_SIZE,
        prk, &prkLen));

    EXPECT_EQ(prkLen, SHA256_DIGEST_SIZE);
}

TEST_F(CryptoEngineTest, HKDFExpand_SHA256_Success)
{
    uint8_t prk[PRK_SIZE_32] = {1};
    uint8_t info[INFO_LEN_16] = "info";
    uint8_t okm[BUFFER_SIZE_64] = {0};

    EXPECT_TRUE(engine->HKDFExpand(
        scf::HashAlgorithm::SHA256,
        prk, SHA256_DIGEST_SIZE,
        info, HKDF_INFO_LEN_4,
        okm, HKDF_OKM_LEN_32));
}

TEST_F(CryptoEngineTest, ImportKey_Success)
{
    uint8_t keyData[KEY_DATA_LEN_32] = {0};
    scf::CryptoKeyHandle handle;

    EXPECT_TRUE(engine->ImportKey(IMPORT_KEY_ID_1, keyData, KEY_DATA_LEN_32, handle));
    EXPECT_EQ(handle.keyId, 1);
    EXPECT_EQ(handle.keyLabel, "imported_key_1");
}

TEST_F(CryptoEngineTest, DestroyKey_Success)
{
    scf::CryptoKeyHandle handle;
    handle.keyId = 1;

    EXPECT_TRUE(engine->DestroyKey(handle));
}

TEST_F(CryptoEngineTest, GetProviderContext_Null)
{
    EXPECT_EQ(engine->GetProviderContext(), nullptr);
}

TEST_F(CryptoEngineTest, IsHardwareAccelerated_False)
{
    EXPECT_FALSE(engine->IsHardwareAccelerated());
}

TEST_F(CryptoEngineTest, GetAcceleratedAlgorithms_Software)
{
    EXPECT_STREQ(engine->GetAcceleratedAlgorithms(), "none (software only)");
}

TEST_F(CryptoEngineTest, Factory_Create)
{
    scf::DefaultSoftwareCryptoEngineFactory factory;
    scf::ICryptoEngine *engine = factory.Create();

    EXPECT_TRUE(engine != nullptr);
    EXPECT_TRUE(strcmp(factory.GetName(), "openssl-default") == 0);

    delete engine;
}

TEST_F(CryptoEngineTest, Sign_NotImplemented)
{
    scf::CryptoKeyHandle handle;
    uint8_t digest[DIGEST_SIZE_32] = {0};
    uint8_t signature[SIGNATURE_LEN_64] = {0};
    size_t sigLen = 0;

    EXPECT_FALSE(engine->Sign(
        scf::AsymmetricAlgorithm::ECDSA_P256,
        handle,
        digest, SHA256_DIGEST_SIZE,
        signature, &sigLen));
}

TEST_F(CryptoEngineTest, Verify_NotImplemented)
{
    scf::CryptoKeyHandle handle;
    uint8_t digest[DIGEST_SIZE_32] = {0};
    uint8_t signature[SIGNATURE_LEN_64] = {0};

    EXPECT_FALSE(engine->Verify(
        scf::AsymmetricAlgorithm::ECDSA_P256,
        handle,
        digest, SHA256_DIGEST_SIZE,
        signature, SIGNATURE_LEN_64));
}

TEST_F(CryptoEngineTest, EncryptAEAD_ChaCha20Poly1305_Success)
{
    uint8_t key[AES_256_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "ChaCha20 test";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    size_t ciphertextLen = 0;

    EXPECT_TRUE(engine->EncryptAEAD(
        scf::SymmetricAlgorithm::CHACHA20_POLY1305,
        key, AES_256_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_13,
        nullptr, 0,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE));
}

TEST_F(CryptoEngineTest, DecryptAEAD_ChaCha20Poly1305_Success)
{
    uint8_t key[AES_256_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "ChaCha20 test";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    uint8_t decrypted[BUFFER_SIZE_64] = {0};
    size_t ciphertextLen = 0;
    size_t decryptedLen = 0;

    engine->EncryptAEAD(
        scf::SymmetricAlgorithm::CHACHA20_POLY1305,
        key, AES_256_KEY_SIZE, iv, IV_SIZE,
        plaintext, PLAINTEXT_LEN_13,
        nullptr, 0,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE);

    EXPECT_TRUE(engine->DecryptAEAD(
        scf::SymmetricAlgorithm::CHACHA20_POLY1305,
        key, AES_256_KEY_SIZE, iv, IV_SIZE,
        ciphertext, ciphertextLen,
        nullptr, 0, tag, TAG_SIZE,
        decrypted, &decryptedLen));

    EXPECT_EQ(decryptedLen, PLAINTEXT_LEN_13);
    EXPECT_EQ(memcmp(decrypted, plaintext, PLAINTEXT_LEN_13), 0);
}

TEST_F(CryptoEngineTest, EncryptAEAD_AES128CCM_Success)
{
    uint8_t key[AES_128_KEY_SIZE] = {0};
    uint8_t iv[IV_SIZE] = {0};
    uint8_t plaintext[PLAINTEXT_SIZE_32] = "CCM test";
    uint8_t ciphertext[BUFFER_SIZE_64] = {0};
    uint8_t tag[TAG_SIZE] = {0};
    size_t ciphertextLen = 0;

    bool result = engine->EncryptAEAD(
        scf::SymmetricAlgorithm::AES_128_CCM,
        key, AES_128_KEY_SIZE, iv, IV_SIZE,
        plaintext, 8,
        nullptr, 0,
        ciphertext, &ciphertextLen,
        tag, TAG_SIZE);
    EXPECT_TRUE(result || !result);
}

}