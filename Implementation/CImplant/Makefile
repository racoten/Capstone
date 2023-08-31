CC=x86_64-w64-mingw32-gcc
CFLAGS=-lwininet -lwinhttp
SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJECTS=getComputerName.o
TARGET=implant.exe

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS) $(OBJECTS)
	$(CC) $(SOURCES) $(OBJECTS) $(CFLAGS) -o $@

clean:
	rm -f $(TARGET)
