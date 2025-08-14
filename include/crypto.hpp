#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace secpack {
struct EncResult {
  std::vector<uint8_t> iv;
  std::vector<uint8_t> hmac;
  uint64_t plainSize{0};
};

bool aes256ctr_encrypt_file(const std::string& inPath, const std::string& outPath,
                            const std::vector<uint8_t>& masterKey, EncResult& outMeta,
                            size_t chunkSize = 1 << 20);

bool aes256ctr_decrypt_file(const std::string& inPath, const std::string& outPath,
                            const std::vector<uint8_t>& masterKey,
                            size_t chunkSize = 1 << 20);

std::vector<uint8_t> sha256_file(const std::string& path, size_t chunkSize = 1 << 20);
std::string hex(const std::vector<uint8_t>& bytes);

// Secure key generation using OpenSSL RNG
std::vector<uint8_t> generate_secure_key(size_t length = 32);
} // namespace secpack

