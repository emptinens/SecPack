#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace secpack {
struct CompressMeta {
  int passes{0};
  uint64_t originalSize{0};
  uint64_t finalSize{0};
};

bool xz_compress_once(const std::string& inPath, const std::string& outPath, int preset = 9, size_t chunk = 1 << 20);

bool xz_compress_multi(const std::string& inPath, const std::string& outPath,
                       double reductionTarget, double minPassGain, int maxPasses,
                       CompressMeta& meta, int preset = 9, size_t chunk = 1 << 20);

bool xz_decompress_passes(const std::string& inPath, const std::string& outPath, int passes,
                          size_t chunk = 1 << 20);
} // namespace secpack

