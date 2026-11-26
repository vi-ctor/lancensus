CLANG     ?= clang
CC        ?= cc
CFLAGS    ?= -O2 -g -Wall -Wextra
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
BPF_INC   := $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH))
BUILD     := build

.PHONY: all check smoke clean

# Linux only: the BPF object and the loader.
all: lancensus lancensus.bpf.o

lancensus.bpf.o: src/lancensus.bpf.c src/lancensus.h
	$(CLANG) -O2 -g -Wall -target bpf $(BPF_INC) -c $< -o $@

lancensus: src/main.c src/device.c src/device.h src/lancensus.h
	$(CC) $(CFLAGS) -o $@ src/main.c src/device.c -lbpf -lelf -lz

# Portable (Linux or macOS): parser tests under ASan/UBSan.
check:
	mkdir -p $(BUILD)
	python3 tests/packets.py dump $(BUILD)/pkts
	$(CC) -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer \
		-Isrc -o $(BUILD)/test_parse tests/test_parse.c src/device.c
	$(BUILD)/test_parse $(BUILD)/pkts

# Linux, root: end-to-end with a veth pair and a network namespace.
smoke: all
	tests/smoke.sh

clean:
	rm -rf $(BUILD) lancensus lancensus.bpf.o
