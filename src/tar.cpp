#include "tar.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;
namespace secpack {

#pragma pack(push,1)
struct TarHeader {
  char name[100];
  char mode[8];
  char uid[8];
  char gid[8];
  char size[12];
  char mtime[12];
  char chksum[8];
  char typeflag;
  char linkname[100];
  char magic[6];
  char version[2];
  char uname[32];
  char gname[32];
  char devmajor[8];
  char devminor[8];
  char prefix[155];
  char pad[12];
};
#pragma pack(pop)

static void set_octal(char* dst, size_t len, uint64_t value) {
  memset(dst, 0, len);
  snprintf(dst, len, "%0*llo", (int)(len-1), (unsigned long long)value);
}

static void compute_checksum(TarHeader& h) {
  memset(h.chksum, ' ', sizeof(h.chksum));
  unsigned int sum = 0;
  const unsigned char* p = reinterpret_cast<const unsigned char*>(&h);
  for (size_t i = 0; i < sizeof(TarHeader); ++i) sum += p[i];
  snprintf(h.chksum, sizeof(h.chksum), "%06o\0 ", sum);
}

bool tar_write(const std::string& outPath,
               const std::vector<TarEntry>& entries,
               const std::vector<std::string>& filePaths) {
  if (entries.size() != filePaths.size()) return false;
  FILE* out = fopen(outPath.c_str(), "wb");
  if (!out) return false;
  const size_t block = 512;
  std::vector<char> zero(block, 0);

  for (size_t i = 0; i < entries.size(); ++i) {
    const auto& e = entries[i];
    TarHeader h{};
    memset(&h, 0, sizeof(h));
    strncpy(h.name, e.name.c_str(), sizeof(h.name));
    strncpy(h.mode, "0000777", 7);
    strncpy(h.uid, "0000000", 7);
    strncpy(h.gid, "0000000", 7);
    set_octal(h.size, sizeof(h.size), e.size);
    set_octal(h.mtime, sizeof(h.mtime), (uint64_t) time(nullptr));
    h.typeflag = '0';
    memcpy(h.magic, "ustar", 5);
    memcpy(h.version, "00", 2);
    compute_checksum(h);

    fwrite(&h, 1, sizeof(h), out);

    FILE* in = fopen(filePaths[i].c_str(), "rb");
    if (!in) { fclose(out); return false; }
    uint64_t remaining = e.size;
    std::vector<char> buf(64*1024);
    while (remaining > 0) {
      size_t toRead = (size_t) std::min<uint64_t>(buf.size(), remaining);
      size_t rd = fread(buf.data(), 1, toRead, in);
      if (rd == 0) break;
      fwrite(buf.data(), 1, rd, out);
      remaining -= rd;
    }
    fclose(in);

    size_t pad = (block - (e.size % block)) % block;
    if (pad) fwrite(zero.data(), 1, pad, out);
  }

  fwrite(zero.data(), 1, block, out);
  fwrite(zero.data(), 1, block, out);
  fclose(out);
  return true;
}

} // namespace secpack
