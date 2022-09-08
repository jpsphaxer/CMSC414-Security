CC=gcc
CFLAGS= -g -Wall
LFLAGS= -lcrypto -lssl

TARGET=hybridEncrypt


$(TARGET): $(TARGET).c
	$(CC) $( CFLAGS) $(TARGET).c -o $(TARGET) $(LFLAGS)

clean: 
	$(RM) $(TARGET)