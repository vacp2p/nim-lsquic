# Windows-only NASM build helpers for BoringSSL objects.
ifeq ($(OS),Windows_NT)
WINDOWS := 1
else
WINDOWS := 0
endif

.PHONY: all windows-boringssl

ifeq ($(WINDOWS),1)
ASM_LIST_RAW := $(file < scripts/boringssl_win_nasm.list)
ASM_LIST := $(filter-out ,$(strip $(ASM_LIST)))
all: windows-boringssl

windows-boringssl:
	for f in $(ASM_LIST); do \
		nasm -f win64 $$f -o $$(basename $$f .asm).o; \
	done
	
else
all:
	@echo "windows-boringssl is a Windows-only target (detected OS=$(OS))"

windows-boringssl:
	@echo "windows-boringssl is a Windows-only target (detected OS=$(OS))"
endif
