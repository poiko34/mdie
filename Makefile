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

TEST_TARGET = test/test_rva_to_offset

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ -lm

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): test/test_rva_to_offset.c src/utils.c
	$(CC) $(CFLAGS) test/test_rva_to_offset.c src/utils.c -o $@ -lm

clean:
	rm -rf build $(TARGET) $(TEST_TARGET)

.PHONY: clean test