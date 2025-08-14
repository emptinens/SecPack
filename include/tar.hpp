#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace secpack {
struct TarEntry {
  std::string name;
  uint64_t size;
};

bool tar_write(const std::string& outPath,
               const std::vector<TarEntry>& entries,
               const std::vector<std::string>& filePaths);
}
