# Windows-only NASM build helpers for BoringSSL objects.
ifeq ($(OS),Windows_NT)
WINDOWS := 1
else
WINDOWS := 0
endif

.PHONY: all windows-boringssl

ifeq ($(WINDOWS),1)
all: windows-boringssl

windows-boringssl:
	git -C ./libs/boringssl/third_party/fiat/ apply ../../../p256_64.h.patch
	nasm -f win64 ./libs/boringssl/gen/bcm/aes-gcm-avx2-x86_64-win.asm -o aes-gcm-avx2-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/aes-gcm-avx512-x86_64-win.asm -o aes-gcm-avx512-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/aesni-gcm-x86_64-win.asm -o aesni-gcm-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/aesni-x86-win.asm -o aesni-x86-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/aesni-x86_64-win.asm -o aesni-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/ghash-ssse3-x86-win.asm -o ghash-ssse3-x86-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/ghash-ssse3-x86_64-win.asm -o ghash-ssse3-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/ghash-x86-win.asm -o ghash-x86-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/ghash-x86_64-win.asm -o ghash-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/p256-x86_64-asm-win.asm -o p256-x86_64-asm-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/p256_beeu-x86_64-asm-win.asm -o p256_beeu-x86_64-asm-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/rdrand-x86_64-win.asm -o rdrand-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/rsaz-avx2-win.asm -o rsaz-avx2-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/sha1-x86_64-win.asm -o sha1-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/sha256-x86_64-win.asm -o sha256-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/sha512-x86_64-win.asm -o sha512-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/vpaes-x86-win.asm -o vpaes-x86-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/vpaes-x86_64-win.asm -o vpaes-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/x86-mont-win.asm -o x86-mont-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/x86_64-mont-win.asm -o x86_64-mont-win.o
	nasm -f win64 ./libs/boringssl/gen/bcm/x86_64-mont5-win.asm -o x86_64-mont5-win.o
	nasm -f win64 ./libs/boringssl/gen/crypto/md5-x86_64-win.asm -o md5-x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/crypto/chacha20_poly1305_x86_64-win.asm -o chacha20_poly1305_x86_64-win.o
	nasm -f win64 ./libs/boringssl/gen/crypto/chacha-x86_64-win.asm -o chacha-x86_64-win.o
else
all:
	@echo "windows-boringssl is a Windows-only target (detected OS=$(OS))"

windows-boringssl:
	@echo "windows-boringssl is a Windows-only target (detected OS=$(OS))"
endif
