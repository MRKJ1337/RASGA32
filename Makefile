CC = arm-linux-gnueabi-gcc
CFLAGS = -Wall -Wextra --static -g -fno-PIE

TARGET = vuln
SRC = vuln.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)