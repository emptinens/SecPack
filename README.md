# SecPack

Multi-pass XZ compression + AES-256-CTR encryption tool with CLI and optional Qt GUI.

## Build (Arch Linux)

```bash
sudo pacman -Syu --needed cmake gcc make pkgconf openssl xz
# For GUI:
sudo pacman -S --needed qt6-base

cd /home/xxx/Desktop/projectc
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

GUI target is built by default if Qt6 is available. To disable:
```bash
cmake -S . -B build -DSECPACK_BUILD_GUI=OFF
```

## CLI Usage

```bash
./build/secpack pack <in> <out.enc> <keyfile> [reduction=0.6]
./build/secpack unpack <in.enc> <out> <keyfile> [passes]
./build/secpack hash <file>
```

- Create a 32-byte key:
```bash
head -c 32 /dev/urandom > key.bin
```

- Pack example:
```bash
./build/secpack pack input.file output.enc key.bin 0.6
# writes output.enc and output.enc.json (contains passes)
```

- Unpack example:
```bash
./build/secpack unpack output.enc restored.file key.bin <passes>
```

## GUI

Run the GUI if built:
```bash
./build/secpack_gui
```
Provides fields to choose files and key, set reduction target, pack/unpack, and hash.

## License

MIT
