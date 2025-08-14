#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstdio>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

namespace secpack {

static void secure_memzero(void* p, size_t n) {
  volatile unsigned char* vp = static_cast<volatile unsigned char*>(p);
  while (n--) *vp++ = 0;
}

std::vector<uint8_t> generate_secure_key(size_t length) {
  if (length < 16) throw std::invalid_argument("key too short");
  std::vector<uint8_t> k(length);
  if (RAND_bytes(k.data(), (int)k.size()) != 1) throw std::runtime_error("RAND_bytes failed");
  return k;
}

static void derive_keys(const std::vector<uint8_t>& master, std::vector<uint8_t>& aes, std::vector<uint8_t>& mac) {
  unsigned int outlen = 0;
  aes.resize(32);
  mac.resize(32);
  HMAC(EVP_sha256(), master.data(), (int)master.size(), (const unsigned char*)"aes", 3, aes.data(), &outlen);
  HMAC(EVP_sha256(), master.data(), (int)master.size(), (const unsigned char*)"hmac", 4, mac.data(), &outlen);
}

std::string hex(const std::vector<uint8_t>& b) {
  static const char* k = "0123456789abcdef";
  std::string s;
  s.resize(b.size() * 2);
  for (size_t i = 0; i < b.size(); ++i) {
    s[2*i]   = k[b[i] >> 4];
    s[2*i+1] = k[b[i] & 0x0F];
  }
  return s;
}

std::vector<uint8_t> sha256_file(const std::string& path, size_t chunkSize) {
  std::vector<uint8_t> out(32);
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) return {};
  std::vector<uint8_t> buf(chunkSize);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  while (true) {
    size_t rd = fread(buf.data(), 1, buf.size(), f);
    if (rd == 0) break;
    SHA256_Update(&ctx, buf.data(), rd);
  }
  fclose(f);
  SHA256_Final(out.data(), &ctx);
  return out;
}

bool aes256ctr_encrypt_file(const std::string& inPath, const std::string& outPath,
                            const std::vector<uint8_t>& masterKey, EncResult& outMeta,
                            size_t chunkSize) {
  std::vector<uint8_t> aes, macKey;
  derive_keys(masterKey, aes, macKey);
  outMeta.iv.resize(16);
  RAND_bytes(outMeta.iv.data(), (int)outMeta.iv.size());

  FILE* in = fopen(inPath.c_str(), "rb");
  if (!in) return false;
  FILE* out = fopen(outPath.c_str(), "wb");
  if (!out) { fclose(in); return false; }

  const unsigned char magic[] = { 'E','N','C','1' };
  fwrite(magic, 1, sizeof(magic), out);
  fwrite(outMeta.iv.data(), 1, outMeta.iv.size(), out);

  HMAC_CTX* hctx = HMAC_CTX_new();
  HMAC_Init_ex(hctx, macKey.data(), (int)macKey.size(), EVP_sha256(), nullptr);
  HMAC_Update(hctx, magic, sizeof(magic));
  HMAC_Update(hctx, outMeta.iv.data(), outMeta.iv.size());

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, aes.data(), outMeta.iv.data());

  std::vector<uint8_t> inbuf(chunkSize), outbuf(chunkSize + 16);
  int outlen = 0;
  outMeta.plainSize = 0;

  while (true) {
    size_t rd = fread(inbuf.data(), 1, inbuf.size(), in);
    if (rd == 0) break;
    EVP_EncryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)rd);
    fwrite(outbuf.data(), 1, outlen, out);
    HMAC_Update(hctx, outbuf.data(), outlen);
    outMeta.plainSize += rd;
  }
  EVP_EncryptFinal_ex(ctx, outbuf.data(), &outlen);
  if (outlen) {
    fwrite(outbuf.data(), 1, outlen, out);
    HMAC_Update(hctx, outbuf.data(), outlen);
  }

  outMeta.hmac.resize(32);
  unsigned int maclen = 0;
  HMAC_Final(hctx, outMeta.hmac.data(), &maclen);
  fwrite(outMeta.hmac.data(), 1, outMeta.hmac.size(), out);

  EVP_CIPHER_CTX_free(ctx);
  HMAC_CTX_free(hctx);
  fclose(in);
  fclose(out);
  return true;
}

bool aes256ctr_decrypt_file(const std::string& inPath, const std::string& outPath,
                            const std::vector<uint8_t>& masterKey, size_t chunkSize) {
  std::vector<uint8_t> aes, macKey;
  derive_keys(masterKey, aes, macKey);

  FILE* in = fopen(inPath.c_str(), "rb");
  if (!in) return false;
  FILE* out = fopen(outPath.c_str(), "wb");
  if (!out) { fclose(in); return false; }

  unsigned char magic[4];
  if (fread(magic, 1, 4, in) != 4 || magic[0] != 'E' || magic[1] != 'N' || magic[2] != 'C' || magic[3] != '1') {
    fclose(in); fclose(out); return false;
  }
  std::vector<uint8_t> iv(16);
  if (fread(iv.data(), 1, iv.size(), in) != iv.size()) {
    fclose(in); fclose(out); return false;
  }

  // compute mac over ciphertext to verify
  HMAC_CTX* hctx = HMAC_CTX_new();
  HMAC_Init_ex(hctx, macKey.data(), (int)macKey.size(), EVP_sha256(), nullptr);
  HMAC_Update(hctx, magic, 4);
  HMAC_Update(hctx, iv.data(), iv.size());

  // find file size
  fseek(in, 0, SEEK_END);
  long total = ftell(in);
  fseek(in, 0, SEEK_SET);
  long header = 4 + 16; // magic + iv
  long macOffset = total - 32;
  if (macOffset < header) { fclose(in); fclose(out); return false; }

  // read and decrypt
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, aes.data(), iv.data());

  std::vector<uint8_t> inbuf(chunkSize), outbuf(chunkSize + 16);
  int outlen = 0;
  long pos = header;

  fseek(in, header, SEEK_SET);
  while (pos < macOffset) {
    size_t toRead = (size_t)std::min<long>(chunkSize, macOffset - pos);
    size_t rd = fread(inbuf.data(), 1, toRead, in);
    if (rd == 0) break;
    HMAC_Update(hctx, inbuf.data(), rd);
    EVP_DecryptUpdate(ctx, outbuf.data(), &outlen, inbuf.data(), (int)rd);
    fwrite(outbuf.data(), 1, outlen, out);
    pos += rd;
  }
  EVP_DecryptFinal_ex(ctx, outbuf.data(), &outlen);
  if (outlen) fwrite(outbuf.data(), 1, outlen, out);

  // verify mac
  std::vector<uint8_t> mac(32);
  fseek(in, macOffset, SEEK_SET);
  fread(mac.data(), 1, mac.size(), in);

  std::vector<uint8_t> calc(32);
  unsigned int maclen = 0;
  HMAC_Final(hctx, calc.data(), &maclen);

  EVP_CIPHER_CTX_free(ctx);
  HMAC_CTX_free(hctx);
  fclose(in);
  fclose(out);

  if (mac != calc) return false;
  return true;
}

} // namespace secpack

