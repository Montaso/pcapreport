# pcapreport - analizator ruchu TCP/UDP z plików pcap/pcapng
# Zależności: kompilator C11, zlib (libz), libm.

CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter -Wno-format-truncation
LDLIBS  += -lz -lm

PREFIX  ?= /usr/local
BIN     := pcapreport
GEN     := tools/gen_samples

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
DEP := $(OBJ:.o=.d)

SAMPLES := samples/normal.pcap samples/attacks.pcap samples/mixed.pcapng

.PHONY: all clean samples demo test install uninstall debug

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

build:
	mkdir -p build

-include $(DEP)

$(GEN): tools/gen_samples.c
	$(CC) $(CFLAGS) -o $@ $< -lm

# synthetic test captures (normal traffic, attacks, pcapng + IPv6)
samples: $(GEN)
	mkdir -p samples
	./$(GEN) samples

demo: $(BIN) samples
	./$(BIN) -c -o out/normal  samples/normal.pcap
	./$(BIN) -c -o out/attacks samples/attacks.pcap
	./$(BIN) -c -o out/mixed   samples/mixed.pcapng
	./$(BIN) -q -o out/all     samples/normal.pcap samples/attacks.pcap samples/mixed.pcapng

test: $(BIN) samples
	./tests/run_tests.sh

debug: CFLAGS := -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(BIN)

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -rf build $(BIN) $(GEN) out
