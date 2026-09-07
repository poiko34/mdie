CC = i686-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11

TARGET = test32.exe
SRC = test32exe.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)

.PHONY: clean
