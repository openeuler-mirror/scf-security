#include <gtest/gtest.h>
#include <unistd.h>

#include <string>

#include "constant_def.h"
#include "openssl_adaptor.h"

#include "scf.h"
#include "scf_errno.h"

using namespace scf;

namespace test {
class TestCertExtension : public ::testing::Test {
protected:
    void SetUp() override
    {
        char libPath[] = "/usr/lib64";
        ASSERT_EQ(SCF_Init(SCF_INIT_FLAG_OPENSSL, libPath), SCF_SUCCESS);
        ctx_ = SCF_CreatePolicyCtx();
        ASSERT_NE(ctx_, nullptr);
    }

    void TearDown() override
    {
        if (obj_ != nullptr) {
            SCF_FreePolicyObj(&obj_);
        }
        if (ctx_ != nullptr) {
            SCF_FreePolicyCtx(&ctx_);
        }
        SCF_DeInit();
    }

    void *LoadCert(const char *certName)
    {
        EXPECT_EQ(SCF_SetPolicy(ctx_, SCF_ROLE_SERVER, SCF_VERIFY_DEFAULT, SCF_POLICY_HIGH), SCF_SUCCESS);
        std::string certPath = std::string(PROJECT_SOURCE_DIR) + "/test/test_data/certificate/" + certName;
        SCF_FILE_CTX *fileCtx = SCF_FileCtxNew();
        EXPECT_NE(fileCtx, nullptr);
        auto *path = reinterpret_cast<uint8_t *>(const_cast<char *>(certPath.c_str()));
        EXPECT_EQ(
            SCF_FileCtxSetBuf(fileCtx, SCF_STORE_FILE_PATH, path, certPath.size(), SCF_STORE_FORMAT_PEM), SCF_SUCCESS);
        EXPECT_EQ(SCF_AddCert(ctx_, fileCtx, SCF_CERT_TYPE_EE), SCF_SUCCESS);
        SCF_FileCtxFree(&fileCtx);
        obj_ = SCF_CreatePolicyObj(ctx_);
        EXPECT_NE(obj_, nullptr);
        EXPECT_EQ(SCF_SetFd(obj_, STDOUT_FILENO), SCF_SUCCESS);
        return SCF_GetCurrentCert(obj_);
    }

    OpenSSLAdapter adapter_;
    SCF_PolicyCtx *ctx_ = nullptr;
    SCF_PolicyObj *obj_ = nullptr;
};

TEST_F(TestCertExtension, ReadsCanonicalUtf8Values)
{
    void *cert = LoadCert("rbac_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_NODE_ID, value), SCF_SUCCESS);
    EXPECT_EQ(value, "node-cert");
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_RBAC_ROLE, value), SCF_SUCCESS);
    EXPECT_EQ(value, "master");
}

TEST_F(TestCertExtension, ReadsSlaveRole)
{
    void *cert = LoadCert("rbac_slave_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_RBAC_ROLE, value), SCF_SUCCESS);
    EXPECT_EQ(value, "slave");
}

TEST_F(TestCertExtension, ReportsAbsentExtension)
{
    void *cert = LoadCert("rbac_node_only_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value = "unchanged";
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_RBAC_ROLE, value), SCF_SSL_ERR_CERT_EXT_ABSENT);
    EXPECT_TRUE(value.empty());
}

TEST_F(TestCertExtension, RejectsInvalidInput)
{
    std::string value = "unchanged";
    EXPECT_EQ(adapter_.GetCertExtensionByOid(nullptr, SCF_OID_NODE_ID, value), SCF_ERRNO_NULL_INPUT);
    EXPECT_TRUE(value.empty());
    char cert = 0;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(&cert, nullptr, value), SCF_ERRNO_NULL_INPUT);
}

TEST_F(TestCertExtension, RejectsDuplicateNodeIdExtension)
{
    void *cert = LoadCert("rbac_duplicate_node_id_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_NODE_ID, value), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestCertExtension, RejectsDuplicateRoleExtension)
{
    void *cert = LoadCert("rbac_duplicate_role_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_RBAC_ROLE, value), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestCertExtension, RejectsNonCanonicalLongFormLength)
{
    void *cert = LoadCert("rbac_noncanonical_length_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_NODE_ID, value), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestCertExtension, RejectsLeadingZeroLengthOctet)
{
    void *cert = LoadCert("rbac_leading_zero_length_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_NODE_ID, value), SCF_SSL_ERR_PARSE_CERT);
}

TEST_F(TestCertExtension, RejectsInvalidUtf8)
{
    void *cert = LoadCert("rbac_invalid_utf8_cert.pem");
    ASSERT_NE(cert, nullptr);
    std::string value;
    EXPECT_EQ(adapter_.GetCertExtensionByOid(cert, SCF_OID_NODE_ID, value), SCF_SSL_ERR_PARSE_CERT);
}
}
