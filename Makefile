CC ?= gcc
CPPFLAGS += -Iinclude
CFLAGS = -Wall -Wextra -Wpedantic -std=c11
LDLIBS = -lm

TARGET = mdie
SRC = \
  src/cli/main.c \
  src/cli/print.c \
  src/cli/graph.c \
  src/cli/ui.c \
  src/cli/format.c \
  src/cli/build_output.c \
  src/cli/debug_output.c \
  src/pe/headers.c \
  src/pe/sections.c \
  src/pe/utils.c \
  src/pe/imports.c \
  src/pe/exports.c \
  src/pe/debug.c \
  src/analysis/compiler.c \
  src/analysis/entropy.c
OBJ = $(SRC:src/%.c=build/%.o)
TEST_TARGET = test/test_rva_to_offset
TEST_DATA_DIR_TARGET = test/test_data_directories
HEADERS = $(wildcard include/*/*.h)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@ $(LDLIBS)

build/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJ:.o=.d)

test: $(TARGET) $(TEST_TARGET) $(TEST_DATA_DIR_TARGET)
	./$(TEST_TARGET)
	./$(TEST_DATA_DIR_TARGET)
	python3 test/test_cli.py ./$(TARGET)
	python3 test/test_imports.py ./$(TARGET)
	python3 test/test_compiler.py ./$(TARGET)
	python3 test/test_exports.py ./$(TARGET)
	python3 test/test_debug.py ./$(TARGET)

$(TEST_TARGET): test/test_rva_to_offset.c src/pe/utils.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@ $(LDLIBS)

$(TEST_DATA_DIR_TARGET): test/test_data_directories.c src/pe/headers.c src/pe/utils.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@ $(LDLIBS)

clean:
	rm -rf build $(TARGET) $(TEST_TARGET) $(TEST_DATA_DIR_TARGET)

.PHONY: clean test
