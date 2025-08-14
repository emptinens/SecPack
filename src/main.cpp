#include "compress.hpp"
#include "crypto.hpp"
#include "tar.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <vector>
#include <string>

namespace fs = std::filesystem;
using namespace secpack;

static std::vector<uint8_t> read_key(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::vector<uint8_t> k((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  if (k.size() < 32) throw std::runtime_error("key must be at least 32 bytes");
  k.resize(32);
  return k;
}

static std::string hex8(uint64_t v) {
  char b[17]; snprintf(b, sizeof(b), "%016llx", (unsigned long long) v); return b;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage:\n"
                 "  secpack pack <in> <out.enc> <keyfile> [reduction=0.6]\n"
                 "  secpack unpack <in.enc> <out> <keyfile> [passes]\n"
                 "  secpack hash <file>\n"
                 "  secpack blockpack <in> <out.tar> <keyfile> [block=8388608] [reduction=0.6]\n";
    return 1;
  }
  std::string cmd = argv[1];
  try {
    if (cmd == "hash") {
      if (argc < 3) throw std::runtime_error("hash <file>");
      auto h = sha256_file(argv[2]);
      std::cout << hex(h) << "\n";
      return 0;
    } else if (cmd == "pack") {
      if (argc < 5) throw std::runtime_error("pack <in> <out.enc> <keyfile> [reduction]");
      std::string in = argv[2], out = argv[3], keyf = argv[4];
      double reduction = (argc >= 6) ? std::stod(argv[5]) : 0.6;
      double minGain = 0.02; int maxPasses = 8; int preset = 9; size_t chunk = 1<<20;

      fs::path tmp = fs::path(out).parent_path() / (fs::path(out).filename().string() + ".tmp.xz");
      CompressMeta meta;
      if (!xz_compress_multi(in, tmp.string(), reduction, minGain, maxPasses, meta, preset, chunk))
        throw std::runtime_error("compression failed");

      auto key = read_key(keyf);
      EncResult er;
      if (!aes256ctr_encrypt_file(tmp.string(), out, key, er, chunk))
        throw std::runtime_error("encryption failed");

      fs::remove(tmp);
      std::ofstream jf(out + ".json");
      jf << "{\n  \"passes\": " << meta.passes << ",\n  \"originalSize\": " << meta.originalSize
         << ",\n  \"finalSize\": " << meta.finalSize << "\n}\n";
      std::cout << "OK: encrypted with " << meta.passes << " pass(es)\n";
      return 0;
    } else if (cmd == "unpack") {
      if (argc < 5) throw std::runtime_error("unpack <in.enc> <out> <keyfile> [passes]");
      std::string in = argv[2], out = argv[3], keyf = argv[4];
      int passes = (argc >= 6) ? std::stoi(argv[5]) : 0;

      fs::path tmp = fs::path(out).parent_path() / (fs::path(out).filename().string() + ".tmp.dec");
      auto key = read_key(keyf);
      if (!aes256ctr_decrypt_file(in, tmp.string(), key))
        throw std::runtime_error("decryption failed");

      if (passes > 0) {
        fs::path finalp = fs::path(out).parent_path() / (fs::path(out).filename().string());
        if (!xz_decompress_passes(tmp.string(), finalp.string(), passes))
          throw std::runtime_error("decompression failed");
        fs::remove(tmp);
      } else {
        if (!xz_decompress_passes(tmp.string(), out, 1)) {
          fs::rename(tmp, out);
        } else {
          fs::remove(tmp);
        }
      }
      std::cout << "OK: decrypted\n";
      return 0;
    } else if (cmd == "blockpack") {
      if (argc < 5) throw std::runtime_error("blockpack <in> <out.tar> <keyfile> [block] [reduction]");
      std::string in = argv[2], out = argv[3], keyf = argv[4];
      size_t block = (argc >= 6) ? (size_t) std::stoull(argv[5]) : (8ull<<20);
      double reduction = (argc >= 7) ? std::stod(argv[6]) : 0.6;

      // 1) Solid compression of whole file
      fs::path tmpdir = fs::path(out).parent_path();
      fs::create_directories(tmpdir);
      fs::path solid = tmpdir / (fs::path(out).filename().string() + ".solid.xz");
      CompressMeta meta;
      if (!xz_compress_multi(in, solid.string(), reduction, 0.02, 8, meta, 9))
        throw std::runtime_error("solid compression failed");

      // 2) Split compressed stream into blocks
      std::ifstream sf(solid, std::ios::binary);
      if (!sf) throw std::runtime_error("cannot open solid");

      auto key = read_key(keyf);
      std::vector<TarEntry> entries;
      std::vector<std::string> files;
      uint64_t index = 0;

      while (true) {
        std::vector<char> buf(block);
        sf.read(buf.data(), buf.size());
        std::streamsize got = sf.gcount();
        if (got <= 0) break;
        fs::path part = tmpdir / (std::string("part_") + hex8(index));
        std::ofstream pof(part, std::ios::binary);
        pof.write(buf.data(), got);
        pof.close();

        // encrypt chunk
        fs::path enc = part; enc += ".enc";
        EncResult er;
        if (!aes256ctr_encrypt_file(part.string(), enc.string(), key, er))
          throw std::runtime_error("chunk encrypt failed");
        fs::remove(part);

        entries.push_back({ enc.filename().string(), (uint64_t)fs::file_size(enc) });
        files.push_back(enc.string());
        ++index;
      }

      // 3) Tar encrypted chunks
      if (!tar_write(out, entries, files))
        throw std::runtime_error("tar write failed");

      for (auto& p : files) fs::remove(p);
      fs::remove(solid);
      std::cout << "OK: block-packed solid-compressed stream, blocks=" << entries.size() << " passes=" << meta.passes << "\n";
      return 0;
    } else {
      throw std::runtime_error("unknown command");
    }
  } catch (const std::exception& ex) {
    std::cerr << "Error: " << ex.what() << "\n";
    return 1;
  }
}

