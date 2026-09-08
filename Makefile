CC ?= gcc
CPPFLAGS += -Iinclude
CFLAGS = -Wall -Wextra -Wpedantic -std=c11
LDLIBS = -lm

TARGET = mdie
SRC = src/main.c src/pe.c src/sections.c src/utils.c src/print.c src/graph.c src/imports.c src/compiler.c src/ui.c
OBJ = $(SRC:src/%.c=build/%.o)
TEST_TARGET = test/test_rva_to_offset
TEST_DATA_DIR_TARGET = test/test_data_directories
HEADERS = $(wildcard include/*.h)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@ $(LDLIBS)

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(OBJ:.o=.d)

test: $(TARGET) $(TEST_TARGET) $(TEST_DATA_DIR_TARGET)
	./$(TEST_TARGET)
	./$(TEST_DATA_DIR_TARGET)
	python3 test/test_cli.py ./$(TARGET)
	python3 test/test_imports.py ./$(TARGET)
	python3 test/test_compiler.py ./$(TARGET)

$(TEST_TARGET): test/test_rva_to_offset.c src/utils.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@ $(LDLIBS)

$(TEST_DATA_DIR_TARGET): test/test_data_directories.c src/pe.c src/utils.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o $@ $(LDLIBS)

clean:
	rm -rf build $(TARGET) $(TEST_TARGET) $(TEST_DATA_DIR_TARGET)

.PHONY: clean test
