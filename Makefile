# Loupe - build for POSIX toolchains. Windows uses build.bat (MSVC).
#
#   make              release build          -> build/loupe
#   make test         unit tests under ASan, UBSan and LeakSanitizer
#   make asan         sanitized loupe        -> build/asan/loupe
#   make fuzz         libFuzzer target       -> build/fuzz/fuzz_loupe   (clang)
#   make mutate       mutation fuzzer        -> build/fuzz/mutate
#   make sweep DIR=/usr/bin
#   make clean

CC      ?= cc
STD      = -std=c11
WARN     = -Wall -Wextra -Wpedantic -Wshadow -Werror
CFLAGS  ?= -O2
INCLUDE  = -Isrc
SAN      = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

LIB_SRC  = src/image.c src/mem.c src/out.c src/inspect.c src/pe.c src/elf.c src/term.c
MAIN_SRC = src/main.c

.PHONY: all test asan fuzz mutate sweep clean

all: build/loupe

build/loupe: $(LIB_SRC) $(MAIN_SRC) | build
	$(CC) $(STD) $(WARN) $(CFLAGS) $(INCLUDE) -o $@ $(LIB_SRC) $(MAIN_SRC)

build/asan/loupe: $(LIB_SRC) $(MAIN_SRC) | build/asan
	$(CC) $(STD) $(WARN) $(SAN) $(INCLUDE) -o $@ $(LIB_SRC) $(MAIN_SRC)

asan: build/asan/loupe

build/test_loupe: $(LIB_SRC) tests/test_loupe.c | build
	$(CC) $(STD) $(WARN) $(SAN) $(INCLUDE) -o $@ $(LIB_SRC) tests/test_loupe.c

test: build/test_loupe
	./build/test_loupe

# libFuzzer needs clang; the mutation fuzzer below runs on any compiler.
build/fuzz/fuzz_loupe: $(LIB_SRC) fuzz/fuzz_loupe.c | build/fuzz
	$(CC) $(STD) $(WARN) $(INCLUDE) -g -O1 -fsanitize=address,fuzzer \
		-o $@ $(LIB_SRC) fuzz/fuzz_loupe.c

fuzz: build/fuzz/fuzz_loupe

build/fuzz/mutate: $(LIB_SRC) fuzz/mutate.c | build/fuzz
	$(CC) $(STD) $(WARN) $(SAN) $(INCLUDE) -o $@ $(LIB_SRC) fuzz/mutate.c

mutate: build/fuzz/mutate

DIR ?= /usr/bin
sweep: build/asan/loupe
	find $(DIR) -type f 2>/dev/null | ./build/asan/loupe --batch

build build/asan build/fuzz:
	mkdir -p $@

clean:
	rm -rf build
