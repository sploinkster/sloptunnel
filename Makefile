CC ?= cc
CFLAGS ?= -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -O2
LDLIBS :=

ifeq ($(OS),Windows_NT)
TARGET := build/sloptunnel.exe
LDLIBS += -lws2_32 -ladvapi32
else
TARGET := build/sloptunnel
endif

.PHONY: all clean run-client run-server

all: $(TARGET)

$(TARGET): src/sloptunnel.c | build
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

build:
	mkdir -p build

run-client: $(TARGET)
	$(TARGET) --client --server-ip 18.219.84.252 --transport all --ports auto

run-server: $(TARGET)
	$(TARGET) --server --transport all --ports auto

clean:
	rm -rf build
