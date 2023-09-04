CC=x86_64-w64-mingw32-gcc
CFLAGS=-lwininet -lwinhttp -lws2_32
SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJECTS=
TARGET=implant.exe

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS) $(OBJECTS)
	$(CC) $(SOURCES) $(OBJECTS) $(CFLAGS) -o $@

clean:
	rm -f $(TARGET)
