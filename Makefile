CC ?= gcc

CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude

TARGET = mdie

SRC = \
	src/main.c \
	src/pe.c \
	src/sections.c \
	src/utils.c \
	src/print.c \
	src/graph.c

OBJ = $(SRC:src/%.c=build/%.o)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ -lm

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build $(TARGET)

.PHONY: clean