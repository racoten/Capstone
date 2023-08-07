CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lwininet -lwinhttp
COFFFLAGS =
OBJ = *.o
TARGET = Implant.exe

all: $(TARGET)

$(TARGET): main_objs getComputerName.o
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

main_objs: *.c
	$(CC) $(CFLAGS) -c $^

getComputerName.o: Modules/COFFLoader/getComputerName.c
	$(CC) -O0 $(CFLAGS) -c $< -o $@

clean:
	del $(OBJ)