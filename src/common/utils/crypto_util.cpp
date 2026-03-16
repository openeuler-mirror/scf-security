/*
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

#include "crypto_util.h"

namespace scf {
    CryptoUtil &CryptoUtil::GetInstance()
    {
        static CryptoUtil instance;
        return instance;
    }

    void CryptoUtil::SetExternalDecryptFunction(ExternalDecryptFunction func)
    {
        decryptFunction_ = func == nullptr ? nullptr : *func;
    }

    void CryptoUtil::SetExternalEncryptFunction(ExternalEncryptFunction func)
    {
        encryptFunction_ = func == nullptr ? nullptr : *func;
    }

    bool CryptoUtil::Encrypt(const uint8_t *content, const size_t &contentLen, std::vector<std::byte> &ciphertext)
    {
        return encryptFunction_ != nullptr && encryptFunction_(content, contentLen, ciphertext);
    }

    bool CryptoUtil::Decrypt(const uint8_t *content, const size_t &contentLen, std::vector<std::byte> &plaintext)
    {
        return decryptFunction_ != nullptr && decryptFunction_(content, contentLen, plaintext);
    }
}
