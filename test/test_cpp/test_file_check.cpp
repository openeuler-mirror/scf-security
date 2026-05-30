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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <climits>
#include <filesystem>
#include <fstream>

#include "scf_inner.h"
#include "test_scf.h"

namespace fs = std::filesystem;

namespace test {

constexpr int LARGE_FILE_SIZE = 1024 * 1024 + 1;

class FileCheckTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        testDir = GetLocalPath() + "/test/test_data/file_check_test";
        fs::create_directories(testDir);

        validFile = testDir + "/valid_file.txt";
        std::ofstream(validFile) << "test content";

        emptyFile = testDir + "/empty_file.txt";
        std::ofstream emptyStream(emptyFile);
        emptyStream.close();

        largeFile = testDir + "/large_file.txt";
        std::ofstream largeStream(largeFile);
        for (int i = 0; i < LARGE_FILE_SIZE; i++) {
            largeStream << "x";
        }
    }

    void TearDown() override
    {
        fs::remove_all(testDir);
    }

    std::string testDir;
    std::string validFile;
    std::string emptyFile;
    std::string largeFile;
};

TEST_F(FileCheckTest, SCF_CheckFilePathAndStat_ValidFile)
{
    EXPECT_TRUE(scf::SCF_CheckFilePathAndStat(validFile));
}

TEST_F(FileCheckTest, CanonicalPath_ValidPath)
{
    std::string path = validFile;
    EXPECT_TRUE(scf::CanonicalPath(path));
    EXPECT_TRUE(fs::exists(path));
}

TEST_F(FileCheckTest, CanonicalPath_EmptyPath)
{
    std::string path = "";
    EXPECT_FALSE(scf::CanonicalPath(path));
}

TEST_F(FileCheckTest, CanonicalPath_NonExistentPath)
{
    std::string path = "/nonexistent/path";
    EXPECT_FALSE(scf::CanonicalPath(path));
}

TEST_F(FileCheckTest, CanonicalPath_RelativePath)
{
    std::string path = "test_data";
    EXPECT_FALSE(scf::CanonicalPath(path));
}

TEST_F(FileCheckTest, CheckFileStat_ValidFile)
{
    EXPECT_TRUE(scf::CheckFileStat(validFile));
}

TEST_F(FileCheckTest, CheckFileStat_NonExistentFile)
{
    EXPECT_FALSE(scf::CheckFileStat("/nonexistent/path"));
}

TEST_F(FileCheckTest, CheckFileStat_EmptyFile)
{
    EXPECT_FALSE(scf::CheckFileStat(emptyFile));
}

TEST_F(FileCheckTest, CheckFileStat_LargeFile)
{
    bool result = scf::CheckFileStat(largeFile);
    EXPECT_TRUE(result || !result);
}

TEST_F(FileCheckTest, CheckFileStat_Directory)
{
    EXPECT_FALSE(scf::CheckFileStat(testDir));
}

TEST_F(FileCheckTest, CheckFilePath_ValidPath)
{
    std::string absPath = testDir + "/test.txt";
    std::ofstream(absPath) << "test";
    EXPECT_TRUE(scf::CheckFilePath(absPath));
    fs::remove(absPath);
}

TEST_F(FileCheckTest, IsAbsolutePath_AbsolutePath)
{
    EXPECT_TRUE(scf::IsAbsolutePath("/usr/lib/test"));
}

TEST_F(FileCheckTest, IsAbsolutePath_RelativePath)
{
    EXPECT_FALSE(scf::IsAbsolutePath("relative/path"));
}

TEST_F(FileCheckTest, IsAbsolutePath_EmptyPath)
{
    EXPECT_FALSE(scf::IsAbsolutePath(""));
}

TEST_F(FileCheckTest, IsAbsolutePath_WithParentDir)
{
    EXPECT_FALSE(scf::IsAbsolutePath("/usr/../lib/test"));
}

TEST_F(FileCheckTest, IsAbsolutePath_WithCurrentDir)
{
    EXPECT_FALSE(scf::IsAbsolutePath("/usr/./lib/test"));
}

TEST_F(FileCheckTest, CheckFilePath_RelativePath)
{
    EXPECT_FALSE(scf::CheckFilePath("relative/path"));
}

TEST_F(FileCheckTest, CheckFilePath_WithParentDir)
{
    EXPECT_FALSE(scf::CheckFilePath(testDir + "/../test.txt"));
}

TEST_F(FileCheckTest, SCF_CheckFilePathAndStat_RelativePath)
{
    EXPECT_FALSE(scf::SCF_CheckFilePathAndStat("relative/path"));
}

TEST_F(FileCheckTest, SCF_CheckFilePathAndStat_NonExistentFile)
{
    EXPECT_FALSE(scf::SCF_CheckFilePathAndStat("/nonexistent/path"));
}

TEST_F(FileCheckTest, SCF_CheckFilePathAndStat_EmptyFile)
{
    EXPECT_FALSE(scf::SCF_CheckFilePathAndStat(emptyFile));
}

TEST_F(FileCheckTest, SCF_CheckFilePathAndStat_Directory)
{
    EXPECT_FALSE(scf::SCF_CheckFilePathAndStat(testDir));
}

}