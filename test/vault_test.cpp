#include <vault.h>
#include <gtest/gtest.h>
#include <fstream>

static std::vector<uint8_t> StringToByteArray(const std::string &str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

TEST(VaultTest, BasicCreateUpdateReadTest) {
    std::vector<uint8_t> contents1(StringToByteArray("initial contents"));
    std::vector<uint8_t> contents2(StringToByteArray("updated"));

    auto token = vault::create("vault.bin", "password", contents1);
    EXPECT_FALSE(token.empty());

    vault::update("vault.bin", token, contents2);
    auto read_contents = vault::read("vault.bin", token);

    EXPECT_EQ(read_contents, contents2);
    EXPECT_FALSE(token.empty());
}

TEST(VaultTest, ReadWithPasswordTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));

    auto token = vault::create("vault.bin", "password", contents);
    EXPECT_FALSE(token.empty());

    vault::token_t read_token;
    auto read_contents = vault::read("vault.bin", "password", &read_token);

    EXPECT_EQ(read_contents, contents);
    EXPECT_FALSE(read_token.empty());
}

TEST(VaultTest, ReadWithWrongPasswordTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));

    auto token = vault::create("vault.bin", "password", contents);
    EXPECT_FALSE(token.empty());

    EXPECT_THROW(vault::read("vault.bin", "wrong password"), std::runtime_error);
}

TEST(VaultTest, ReadWithWrongTokenTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));

    auto token = vault::create("vault.bin", "password", contents);
    EXPECT_FALSE(token.empty());

    std::reverse(std::begin(token), std::end(token));
    EXPECT_THROW(vault::read("vault.bin", token), std::runtime_error);
}
