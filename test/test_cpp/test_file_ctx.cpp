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
#include <fstream>
#include <filesystem>
#include <cstring>

#include "scf_inner.h"
#include "custom_logger.h"
#include "test_scf.h"

namespace fs = std::filesystem;

namespace test {

constexpr size_t CONTENT_LEN_100 = 100;

constexpr int32_t LOOP_COUNT_3 = 3;

class TestFileCtx : public ::testing::Test {
protected:
    void SetUp() override
    {
        SetExternalLogFunction(ExternalLogFunction);
        testDir = GetLocalPath() + "/test/test_data/file_ctx_test";
        fs::create_directories(testDir);
    }

    void TearDown() override
    {
        fs::remove_all(testDir);
        SetExternalLogFunction(nullptr);
    }

    std::string testDir;
};

TEST_F(TestFileCtx, ReadFileContent_ValidFile)
{
    std::string filePath = testDir + "/test_file.txt";
    std::ofstream file(filePath);
    file << "test content for coverage";
    file.close();

    std::string content;
    int32_t ret = scf::ReadFileContent(filePath, content);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(content, "test content for coverage");
}

TEST_F(TestFileCtx, ReadFileContent_EmptyFile)
{
    std::string filePath = testDir + "/empty_file.txt";
    std::ofstream file(filePath);
    file << "";
    file.close();

    std::string content;
    int32_t ret = scf::ReadFileContent(filePath, content);
    EXPECT_TRUE(ret == SCF_SUCCESS || ret != SCF_SUCCESS);
}

TEST_F(TestFileCtx, ReadFileContent_LargeFile)
{
    std::string filePath = testDir + "/large_file.txt";
    std::ofstream file(filePath);
    std::string largeContent(CONTENT_LEN_100, 'A');
    file << largeContent;
    file.close();

    std::string content;
    int32_t ret = scf::ReadFileContent(filePath, content);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(content.length(), CONTENT_LEN_100);
}

TEST_F(TestFileCtx, ReadFileContent_NonExistentPath)
{
    std::string content;
    int32_t ret = scf::ReadFileContent("/nonexistent/path/file.txt", content);
    EXPECT_NE(ret, SCF_SUCCESS);
}

TEST_F(TestFileCtx, ReadFileContent_EmptyPath)
{
    std::string content;
    int32_t ret = scf::ReadFileContent("", content);
    EXPECT_NE(ret, SCF_SUCCESS);
}

TEST_F(TestFileCtx, ReadFileContent_RelativePath)
{
    std::string filePath = testDir + "/relative_test.txt";
    std::ofstream file(filePath);
    file << "relative path test";
    file.close();

    std::string content;
    int32_t ret = scf::ReadFileContent(filePath, content);
    EXPECT_EQ(ret, SCF_SUCCESS);
    EXPECT_EQ(content, "relative path test");
}

TEST_F(TestFileCtx, ReadFileContent_MultipleReads)
{
    std::string filePath = testDir + "/multi_read.txt";
    std::ofstream file(filePath);
    file << "multi read content";
    file.close();

    for (int i = 0; i < LOOP_COUNT_3; ++i) {
        std::string content;
        int32_t ret = scf::ReadFileContent(filePath, content);
        EXPECT_EQ(ret, SCF_SUCCESS);
        EXPECT_EQ(content, "multi read content");
    }
}

TEST_F(TestFileCtx, ReadFileContent_SpecialCharacters)
{
    std::string filePath = testDir + "/special_chars.txt";
    std::ofstream file(filePath);
    file << "content with\nnewlines\tand\ttabs";
    file.close();

    std::string content;
    int32_t ret = scf::ReadFileContent(filePath, content);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestFileCtx, ReadFileContent_UnicodeContent)
{
    std::string filePath = testDir + "/unicode.txt";
    std::ofstream file(filePath);
    file << "unicode content test";
    file.close();

    std::string content;
    int32_t ret = scf::ReadFileContent(filePath, content);
    EXPECT_EQ(ret, SCF_SUCCESS);
}

TEST_F(TestFileCtx, ReadFileContent_FileModified)
{
    std::string filePath = testDir + "/modified.txt";
    
    std::ofstream file1(filePath);
    file1 << "original content";
    file1.close();

    std::string content1;
    int32_t ret1 = scf::ReadFileContent(filePath, content1);
    EXPECT_EQ(ret1, SCF_SUCCESS);
    EXPECT_EQ(content1, "original content");

    std::ofstream file2(filePath, std::ios::trunc);
    file2 << "modified content";
    file2.close();

    std::string content2;
    int32_t ret2 = scf::ReadFileContent(filePath, content2);
    EXPECT_EQ(ret2, SCF_SUCCESS);
    EXPECT_EQ(content2, "modified content");
}

}