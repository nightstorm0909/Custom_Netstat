CC = gcc
CFLAGS = -I.

%.o: %.c
	$(CC) -c $< $(CFLAGS)

custom_netstat: main.o utils.o
	$(CC) -o custom_netstat $^ $(CFLAGS)

clean:
	rm *.o