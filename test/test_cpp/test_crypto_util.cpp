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
#include <vector>
#include <cstring>

#include "crypto_util.h"
#include "test_scf.h"

namespace test {

constexpr size_t CONTENT_LEN_3 = 3;
constexpr size_t PLAINTEXT_SIZE_3 = 3;
constexpr size_t CIPHERTEXT_SIZE_3 = 3;
constexpr size_t INDEX_0 = 0;
constexpr size_t INDEX_1 = 1;
constexpr size_t INDEX_2 = 2;
constexpr uint8_t EXPECTED_BYTE_0 = 0xFE;
constexpr uint8_t EXPECTED_BYTE_1 = 0xFD;
constexpr uint8_t EXPECTED_BYTE_2 = 0xFC;

bool MockDecryptFunction(const uint8_t *content, size_t contentLen, std::vector<std::byte> &plaintext)
{
    plaintext.clear();
    plaintext.resize(contentLen);
    for (size_t i = 0; i < contentLen; ++i) {
        plaintext[i] = static_cast<std::byte>(content[i] ^ 0xFF);
    }
    return true;
}

bool MockEncryptFunction(const uint8_t *content, size_t contentLen, std::vector<std::byte> &ciphertext)
{
    ciphertext.clear();
    ciphertext.resize(contentLen);
    for (size_t i = 0; i < contentLen; ++i) {
        ciphertext[i] = static_cast<std::byte>(content[i] ^ 0xFF);
    }
    return true;
}

bool MockFailFunction(const uint8_t *content, size_t contentLen, std::vector<std::byte> &output)
{
    (void)content;
    (void)contentLen;
    (void)output;
    return false;
}

class CryptoUtilTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
    }
    void TearDown() override
    {
        scf::CryptoUtil::GetInstance().SetExternalDecryptFunction(nullptr);
        scf::CryptoUtil::GetInstance().SetExternalEncryptFunction(nullptr);
        SetExternalLogFunction(nullptr);
    }
};

TEST_F(CryptoUtilTest, GetInstance_Singleton)
{
    scf::CryptoUtil &instance1 = scf::CryptoUtil::GetInstance();
    scf::CryptoUtil &instance2 = scf::CryptoUtil::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

TEST_F(CryptoUtilTest, SetExternalDecryptFunction_Valid)
{
    scf::CryptoUtil::GetInstance().SetExternalDecryptFunction(MockDecryptFunction);
    std::vector<std::byte> plaintext;
    uint8_t content[] = {0x01, 0x02, 0x03};

    EXPECT_TRUE(scf::CryptoUtil::GetInstance().Decrypt(content, CONTENT_LEN_3, plaintext));
    EXPECT_EQ(plaintext.size(), PLAINTEXT_SIZE_3);
    EXPECT_EQ(static_cast<uint8_t>(plaintext[INDEX_0]), EXPECTED_BYTE_0);
    EXPECT_EQ(static_cast<uint8_t>(plaintext[INDEX_1]), EXPECTED_BYTE_1);
    EXPECT_EQ(static_cast<uint8_t>(plaintext[INDEX_2]), EXPECTED_BYTE_2);
}

TEST_F(CryptoUtilTest, SetExternalDecryptFunction_Null)
{
    scf::CryptoUtil::GetInstance().SetExternalDecryptFunction(nullptr);
    std::vector<std::byte> plaintext;
    uint8_t content[] = {0x01, 0x02, 0x03};

    EXPECT_FALSE(scf::CryptoUtil::GetInstance().Decrypt(content, CONTENT_LEN_3, plaintext));
}

TEST_F(CryptoUtilTest, SetExternalEncryptFunction_Valid)
{
    scf::CryptoUtil::GetInstance().SetExternalEncryptFunction(MockEncryptFunction);
    std::vector<std::byte> ciphertext;
    uint8_t content[] = {0x01, 0x02, 0x03};

    EXPECT_TRUE(scf::CryptoUtil::GetInstance().Encrypt(content, CONTENT_LEN_3, ciphertext));
    EXPECT_EQ(ciphertext.size(), CIPHERTEXT_SIZE_3);
    EXPECT_EQ(static_cast<uint8_t>(ciphertext[INDEX_0]), EXPECTED_BYTE_0);
    EXPECT_EQ(static_cast<uint8_t>(ciphertext[INDEX_1]), EXPECTED_BYTE_1);
    EXPECT_EQ(static_cast<uint8_t>(ciphertext[INDEX_2]), EXPECTED_BYTE_2);
}

TEST_F(CryptoUtilTest, SetExternalEncryptFunction_Null)
{
    scf::CryptoUtil::GetInstance().SetExternalEncryptFunction(nullptr);
    std::vector<std::byte> ciphertext;
    uint8_t content[] = {0x01, 0x02, 0x03};

    EXPECT_FALSE(scf::CryptoUtil::GetInstance().Encrypt(content, CONTENT_LEN_3, ciphertext));
}

TEST_F(CryptoUtilTest, Decrypt_FailFunction)
{
    scf::CryptoUtil::GetInstance().SetExternalDecryptFunction(MockFailFunction);
    std::vector<std::byte> plaintext;
    uint8_t content[] = {0x01, 0x02, 0x03};

    EXPECT_FALSE(scf::CryptoUtil::GetInstance().Decrypt(content, CONTENT_LEN_3, plaintext));
}

TEST_F(CryptoUtilTest, Encrypt_FailFunction)
{
    scf::CryptoUtil::GetInstance().SetExternalEncryptFunction(MockFailFunction);
    std::vector<std::byte> ciphertext;
    uint8_t content[] = {0x01, 0x02, 0x03};

    EXPECT_FALSE(scf::CryptoUtil::GetInstance().Encrypt(content, CONTENT_LEN_3, ciphertext));
}

TEST_F(CryptoUtilTest, Decrypt_EmptyContent)
{
    scf::CryptoUtil::GetInstance().SetExternalDecryptFunction(MockDecryptFunction);
    std::vector<std::byte> plaintext;

    EXPECT_TRUE(scf::CryptoUtil::GetInstance().Decrypt(nullptr, 0, plaintext));
    EXPECT_EQ(plaintext.size(), 0);
}

TEST_F(CryptoUtilTest, Encrypt_EmptyContent)
{
    scf::CryptoUtil::GetInstance().SetExternalEncryptFunction(MockEncryptFunction);
    std::vector<std::byte> ciphertext;

    EXPECT_TRUE(scf::CryptoUtil::GetInstance().Encrypt(nullptr, 0, ciphertext));
    EXPECT_EQ(ciphertext.size(), 0);
}

}