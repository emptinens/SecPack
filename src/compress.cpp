#include "compress.hpp"
#include <lzma.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

namespace secpack {

static bool xz_stream_copy(FILE* in, FILE* out, int preset, size_t chunk) {
  std::vector<uint8_t> inbuf(chunk), outbuf(chunk);
  lzma_stream strm = LZMA_STREAM_INIT;
  lzma_ret ret = lzma_easy_encoder(&strm, preset | LZMA_PRESET_EXTREME, LZMA_CHECK_CRC64);
  if (ret != LZMA_OK) return false;

  strm.next_in = nullptr;
  strm.avail_in = 0;
  strm.next_out = outbuf.data();
  strm.avail_out = outbuf.size();

  bool ok = true;
  lzma_action action = LZMA_RUN;
  while (true) {
    if (strm.avail_in == 0 && action != LZMA_FINISH) {
      size_t rd = fread(inbuf.data(), 1, inbuf.size(), in);
      strm.next_in = inbuf.data();
      strm.avail_in = rd;
      if (rd == 0) action = LZMA_FINISH;
    }

    ret = lzma_code(&strm, action);
    if (strm.avail_out == 0 || ret == LZMA_STREAM_END) {
      size_t toWrite = outbuf.size() - strm.avail_out;
      if (toWrite) fwrite(outbuf.data(), 1, toWrite, out);
      strm.next_out = outbuf.data();
      strm.avail_out = outbuf.size();
    }

    if (ret == LZMA_STREAM_END) break;
    if (ret != LZMA_OK) { ok = false; break; }
  }
  lzma_end(&strm);
  return ok;
}

bool xz_compress_once(const std::string& inPath, const std::string& outPath, int preset, size_t chunk) {
  FILE* in = fopen(inPath.c_str(), "rb");
  if (!in) return false;
  FILE* out = fopen(outPath.c_str(), "wb");
  if (!out) { fclose(in); return false; }
  bool ok = xz_stream_copy(in, out, preset, chunk);
  fclose(in);
  fclose(out);
  return ok;
}

bool xz_compress_multi(const std::string& inPath, const std::string& outPath,
                       double reductionTarget, double minPassGain, int maxPasses,
                       CompressMeta& meta, int preset, size_t chunk) {
  fs::path tmpdir = fs::path(outPath).parent_path();
  fs::create_directories(tmpdir);
  fs::path current = inPath;
  uint64_t currentSize = fs::file_size(current);
  meta.originalSize = currentSize;
  int passes = 0;
  uint64_t targetSize = static_cast<uint64_t>(currentSize * (1.0 - reductionTarget));

  while (passes < maxPasses) {
    fs::path next = tmpdir / (current.filename().string() + ".p" + std::to_string(passes+1) + ".xz");
    if (!xz_compress_once(current.string(), next.string(), preset, chunk)) {
      if (current != inPath) fs::remove(next);
      break;
    }
    uint64_t nextSize = fs::file_size(next);
    double gain = (double)(currentSize - nextSize) / (double)currentSize;
    if (nextSize < currentSize && gain >= minPassGain) {
      if (current != inPath) fs::remove(current);
      current = next;
      currentSize = nextSize;
      ++passes;
      if (currentSize <= targetSize) break;
    } else {
      fs::remove(next);
      break;
    }
  }

  meta.passes = passes;
  meta.finalSize = currentSize;
  if (current == inPath) {
    // No useful compression; just copy
    std::error_code ec;
    fs::copy_file(current, outPath, fs::copy_options::overwrite_existing, ec);
    return ec ? false : true;
  } else {
    std::error_code ec;
    fs::rename(current, outPath, ec);
    return ec ? false : true;
  }
}

bool xz_decompress_passes(const std::string& inPath, const std::string& outPath, int passes, size_t chunk) {
  // Since we wrote a single final .xz containing multi-pass-compressed data,
  // we just decompress once to restore original
  FILE* in = fopen(inPath.c_str(), "rb");
  if (!in) return false;
  FILE* out = fopen(outPath.c_str(), "wb");
  if (!out) { fclose(in); return false; }

  // Decode XZ stream
  std::vector<uint8_t> inbuf(chunk), outbuf(chunk);
  lzma_stream strm = LZMA_STREAM_INIT;
  lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
  if (ret != LZMA_OK) { fclose(in); fclose(out); return false; }

  strm.next_in = nullptr;
  strm.avail_in = 0;
  strm.next_out = outbuf.data();
  strm.avail_out = outbuf.size();

  bool ok = true;
  lzma_action action = LZMA_RUN;
  while (true) {
    if (strm.avail_in == 0 && action != LZMA_FINISH) {
      size_t rd = fread(inbuf.data(), 1, inbuf.size(), in);
      strm.next_in = inbuf.data();
      strm.avail_in = rd;
      if (rd == 0) action = LZMA_FINISH;
    }

    ret = lzma_code(&strm, action);
    if (strm.avail_out == 0 || ret == LZMA_STREAM_END) {
      size_t toWrite = outbuf.size() - strm.avail_out;
      if (toWrite) fwrite(outbuf.data(), 1, toWrite, out);
      strm.next_out = outbuf.data();
      strm.avail_out = outbuf.size();
    }
    if (ret == LZMA_STREAM_END) break;
    if (ret != LZMA_OK) { ok = false; break; }
  }
  lzma_end(&strm);
  fclose(in);
  fclose(out);
  return ok;
}

} // namespace secpack

