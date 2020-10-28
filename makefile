CC = gcc
CFLAGS = -lpcap
TARGET = arp-spoof

all: $(TARGET)

$(TARGET): arp-spoof.c
		$(CC) -o arp-spoof arp-spoof.c $(CFLAGS)

clean:
		rm $(TARGET)