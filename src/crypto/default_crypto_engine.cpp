/**
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Secure Communication Framework is licensed under Mulan PSL v2.
 *
 * 基于 OpenSSL 的默认软件密码引擎实现。
 * 作为参考实现，当没有硬件加速模块时使用此实现。
 * 实际集成时，此处应替换为硬件 SDK 的调用。
 */

#include "scf_crypto_engine.h"
#include "custom_logger.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>

namespace scf {

// ============================================================
// 算法映射工具函数
// ============================================================

static const EVP_CIPHER *MapSymmetricAlgo(SymmetricAlgorithm algo)
{
    switch (algo) {
        case SymmetricAlgorithm::AES_128_GCM:      return EVP_aes_128_gcm();
        case SymmetricAlgorithm::AES_256_GCM:      return EVP_aes_256_gcm();
        case SymmetricAlgorithm::AES_128_CCM:      return EVP_aes_128_ccm();
        case SymmetricAlgorithm::CHACHA20_POLY1305: return EVP_chacha20_poly1305();
        default: return nullptr;
    }
}

static const EVP_MD *MapHashAlgo(HashAlgorithm algo)
{
    switch (algo) {
        case HashAlgorithm::SHA256: return EVP_sha256();
        case HashAlgorithm::SHA384: return EVP_sha384();
        case HashAlgorithm::SHA512: return EVP_sha512();
        default: return nullptr;
    }
}

static int MapEcNid(AsymmetricAlgorithm algo)
{
    int result = NID_undef;
    switch (algo) {
        case AsymmetricAlgorithm::ECDSA_P256:
            result = NID_X9_62_prime256v1;
            break;
        case AsymmetricAlgorithm::ECDSA_P384:
            result = NID_secp384r1;
            break;
        case AsymmetricAlgorithm::ECDSA_P521:
            result = NID_secp521r1;
            break;
        default:
            break;
    }
    return result;
}

// ============================================================
// DefaultSoftwareCryptoEngine
// ============================================================

DefaultSoftwareCryptoEngine::DefaultSoftwareCryptoEngine()
    : m_initialized(false)
{
}

DefaultSoftwareCryptoEngine::~DefaultSoftwareCryptoEngine()
{
    Finalize();
}

bool DefaultSoftwareCryptoEngine::Initialize(const CryptoEngineConfig &config)
{
    (void)config;
    // OpenSSL 已在 SCF_Init 阶段初始化，此处无需额外操作
    m_initialized = true;
    CCSEC_LOG_INFO("DefaultSoftwareCryptoEngine initialized");
    return true;
}

void DefaultSoftwareCryptoEngine::Finalize()
{
    m_initialized = false;
    CCSEC_LOG_INFO("DefaultSoftwareCryptoEngine finalized");
}

CryptoEngineCapability DefaultSoftwareCryptoEngine::GetCapability() const
{
    CryptoEngineCapability cap;
    cap.engineName = "OpenSSL Software Engine";
    cap.engineVersion = OPENSSL_VERSION_TEXT;
    cap.hardwareVendor = "Software";
    cap.hardwareAccelerated = false;
    cap.supportsAsyncOperation = false;
    cap.supportsOffload = false;
    cap.maxConcurrentOps = 0;

    cap.symmetricAlgos = {
        SymmetricAlgorithm::AES_128_GCM,
        SymmetricAlgorithm::AES_256_GCM,
        SymmetricAlgorithm::AES_128_CCM,
        SymmetricAlgorithm::CHACHA20_POLY1305,
    };
    cap.asymmetricAlgos = {
        AsymmetricAlgorithm::ECDSA_P256,
        AsymmetricAlgorithm::ECDSA_P384,
        AsymmetricAlgorithm::ECDSA_P521,
    };
    cap.hashAlgos = {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512,
    };
    cap.keyExchangeAlgos = {
        KeyExchangeAlgorithm::ECDHE,
    };

    return cap;
}

bool DefaultSoftwareCryptoEngine::IsInitialized() const
{
    return m_initialized;
}

bool DefaultSoftwareCryptoEngine::EncryptAEAD(
    SymmetricAlgorithm algo, const uint8_t *key, size_t keyLen,
    const uint8_t *iv, size_t ivLen, const uint8_t *plaintext, size_t plaintextLen,
    const uint8_t *aad, size_t aadLen,
    uint8_t *ciphertext, size_t *ciphertextLen, uint8_t *tag, size_t tagLen)
{
    (void)keyLen;
    const EVP_CIPHER *cipher = MapSymmetricAlgo(algo);
    if (cipher == nullptr) {
        CCSEC_LOG_ERROR("EncryptAEAD: unsupported algorithm");
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    bool ok = false;
    do {
        if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) break;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(ivLen), nullptr)) break;

        if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) break;

        int outLen = 0;
        if (aad != nullptr && aadLen > 0) {
            if (!EVP_EncryptUpdate(ctx, nullptr, &outLen, aad, static_cast<int>(aadLen))) break;
        }

        if (!EVP_EncryptUpdate(ctx, ciphertext, &outLen, plaintext, static_cast<int>(plaintextLen))) break;
        *ciphertextLen = static_cast<size_t>(outLen);

        if (!EVP_EncryptFinal_ex(ctx, ciphertext + outLen, &outLen)) break;
        *ciphertextLen += static_cast<size_t>(outLen);

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tagLen), tag)) break;

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool DefaultSoftwareCryptoEngine::DecryptAEAD(
    SymmetricAlgorithm algo, const uint8_t *key, size_t keyLen,
    const uint8_t *iv, size_t ivLen, const uint8_t *ciphertext, size_t ciphertextLen,
    const uint8_t *aad, size_t aadLen, const uint8_t *tag, size_t tagLen,
    uint8_t *plaintext, size_t *plaintextLen)
{
    (void)keyLen;
    const EVP_CIPHER *cipher = MapSymmetricAlgo(algo);
    if (cipher == nullptr) {
        CCSEC_LOG_ERROR("DecryptAEAD: unsupported algorithm");
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    bool ok = false;
    do {
        if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr)) break;
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(ivLen), nullptr)) break;

        if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) break;

        int outLen = 0;
        if (aad != nullptr && aadLen > 0) {
            if (!EVP_DecryptUpdate(ctx, nullptr, &outLen, aad, static_cast<int>(aadLen))) break;
        }

        if (!EVP_DecryptUpdate(ctx, plaintext, &outLen, ciphertext, static_cast<int>(ciphertextLen))) break;
        *plaintextLen = static_cast<size_t>(outLen);

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tagLen),
            const_cast<uint8_t *>(tag))) break;

        // Final 会验证 tag
        if (EVP_DecryptFinal_ex(ctx, plaintext + outLen, &outLen) <= 0) break;
        *plaintextLen += static_cast<size_t>(outLen);

        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool DefaultSoftwareCryptoEngine::ECDHKeyAgreement(
    AsymmetricAlgorithm algo, const uint8_t *peerPublicKey, size_t peerPublicKeyLen,
    uint8_t *sharedSecret, size_t *sharedSecretLen)
{
    int nid = MapEcNid(algo);
    if (nid == NID_undef) return false;

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY *peerKey = nullptr;
    bool ok = false;

    do {
        // 生成本地密钥对
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (pctx == nullptr) break;
        if (EVP_PKEY_keygen_init(pctx) <= 0) break;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) break;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) break;

        // 解析对端公钥
        const uint8_t *peerPtr = peerPublicKey;
        peerKey = d2i_PUBKEY(nullptr, &peerPtr, static_cast<long>(peerPublicKeyLen));
        if (peerKey == nullptr) break;

        // ECDH 派生共享密钥
        EVP_PKEY_CTX *deriveCtx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (deriveCtx == nullptr) break;
        if (EVP_PKEY_derive_init(deriveCtx) <= 0) {
            EVP_PKEY_CTX_free(deriveCtx);
            break;
        }
        if (EVP_PKEY_derive_set_peer(deriveCtx, peerKey) <= 0) {
            EVP_PKEY_CTX_free(deriveCtx);
            break;
        }

        size_t secretLen = 0;
        if (EVP_PKEY_derive(deriveCtx, nullptr, &secretLen) <= 0) {
            EVP_PKEY_CTX_free(deriveCtx);
            break;
        }
        if (EVP_PKEY_derive(deriveCtx, sharedSecret, &secretLen) <= 0) {
            EVP_PKEY_CTX_free(deriveCtx);
            break;
        }
        *sharedSecretLen = secretLen;

        EVP_PKEY_CTX_free(deriveCtx);
        ok = true;
    } while (false);

    if (pkey != nullptr) EVP_PKEY_free(pkey);
    if (pctx != nullptr) EVP_PKEY_CTX_free(pctx);
    if (peerKey != nullptr) EVP_PKEY_free(peerKey);
    return ok;
}

bool DefaultSoftwareCryptoEngine::Sign(
    AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
    const uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *sigLen)
{
    // NOTE: requires EVP_PKEY recovery from key for signing
    (void)algo;
    (void)key;
    (void)digest;
    (void)digestLen;
    (void)signature;
    (void)sigLen;
    CCSEC_LOG_WARN("DefaultSoftwareCryptoEngine::Sign not fully implemented");
    return false;
}

bool DefaultSoftwareCryptoEngine::Verify(
    AsymmetricAlgorithm algo, const CryptoKeyHandle &key,
    const uint8_t *digest, size_t digestLen, const uint8_t *signature, size_t sigLen)
{
    (void)algo;
    (void)key;
    (void)digest;
    (void)digestLen;
    (void)signature;
    (void)sigLen;
    CCSEC_LOG_WARN("DefaultSoftwareCryptoEngine::Verify not fully implemented");
    return false;
}

bool DefaultSoftwareCryptoEngine::Hash(
    HashAlgorithm algo, const uint8_t *data, size_t dataLen,
    uint8_t *digest, size_t *digestLen)
{
    const EVP_MD *md = MapHashAlgo(algo);
    if (md == nullptr) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;

    bool ok = true;
    unsigned int outLen = 0;
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, dataLen) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &outLen) != 1) {
        ok = false;
    }
    *digestLen = static_cast<size_t>(outLen);
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool DefaultSoftwareCryptoEngine::HMAC(
    HashAlgorithm algo, const uint8_t *key, size_t keyLen,
    const uint8_t *data, size_t dataLen, uint8_t *mac, size_t *macLen)
{
    const EVP_MD *md = MapHashAlgo(algo);
    if (md == nullptr) return false;

    unsigned int outLen = 0;
    uint8_t *result = ::HMAC(md, key, static_cast<int>(keyLen), data, dataLen, mac, &outLen);
    if (result == nullptr) return false;
    *macLen = static_cast<size_t>(outLen);
    return true;
}

bool DefaultSoftwareCryptoEngine::HKDFExtract(
    HashAlgorithm algo, const uint8_t *salt, size_t saltLen,
    const uint8_t *ikm, size_t ikmLen, uint8_t *prk, size_t *prkLen)
{
    const EVP_MD *md = MapHashAlgo(algo);
    if (md == nullptr) return false;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (pctx == nullptr) return false;

    bool ok = false;
    do {
        if (EVP_PKEY_derive_init(pctx) <= 0) break;
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, static_cast<int>(saltLen)) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, static_cast<int>(ikmLen)) <= 0) break;
        if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0) break;

        size_t outLen = EVP_MD_size(md);
        if (EVP_PKEY_derive(pctx, prk, &outLen) <= 0) break;
        *prkLen = outLen;
        ok = true;
    } while (false);

    EVP_PKEY_CTX_free(pctx);
    return ok;
}

bool DefaultSoftwareCryptoEngine::HKDFExpand(
    HashAlgorithm algo, const uint8_t *prk, size_t prkLen,
    const uint8_t *info, size_t infoLen, uint8_t *okm, size_t okmLen)
{
    const EVP_MD *md = MapHashAlgo(algo);
    if (md == nullptr) return false;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (pctx == nullptr) return false;

    bool ok = false;
    do {
        if (EVP_PKEY_derive_init(pctx) <= 0) break;
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, static_cast<int>(prkLen)) <= 0) break;
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, static_cast<int>(infoLen)) <= 0) break;
        if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) break;

        if (EVP_PKEY_derive(pctx, okm, &okmLen) <= 0) break;
        ok = true;
    } while (false);

    EVP_PKEY_CTX_free(pctx);
    return ok;
}

bool DefaultSoftwareCryptoEngine::RandomBytes(uint8_t *buffer, size_t len)
{
    return RAND_bytes(buffer, static_cast<int>(len)) == 1;
}

bool DefaultSoftwareCryptoEngine::ImportKey(
    uint64_t keyId, const uint8_t *keyData, size_t keyDataLen, CryptoKeyHandle &handle)
{
    handle.keyId = keyId;
    handle.keyLabel = "imported_key_" + std::to_string(keyId);
    handle.engineContext = nullptr;  // 软件实现不保留上下文
    // 实际使用中应解析 keyData 并存储到安全内存
    (void)keyData;
    (void)keyDataLen;
    return true;
}

bool DefaultSoftwareCryptoEngine::DestroyKey(const CryptoKeyHandle &handle)
{
    (void)handle;
    return true;
}

// ============================================================
// Provider 集成（软件实现无 Provider）
// ============================================================

void *DefaultSoftwareCryptoEngine::GetProviderContext() const
{
    // 软件实现不使用 OpenSSL Provider 机制，返回 nullptr
    // AbstractTLSAdaptor 将使用默认的 SSL_CTX_new()
    return nullptr;
}

bool DefaultSoftwareCryptoEngine::IsHardwareAccelerated() const
{
    return false;
}

const char *DefaultSoftwareCryptoEngine::GetAcceleratedAlgorithms() const
{
    return "none (software only)";
}

// ============================================================
// DefaultSoftwareCryptoEngineFactory
// ============================================================

ICryptoEngine *DefaultSoftwareCryptoEngineFactory::Create()
{
    return new DefaultSoftwareCryptoEngine();
}

const char *DefaultSoftwareCryptoEngineFactory::GetName() const
{
    return "openssl-default";
}

}  // namespace scf
