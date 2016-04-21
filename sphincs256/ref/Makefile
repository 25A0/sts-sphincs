
all: *.o

INCDIRS=-I./include

test_chacha12.o: test_chacha12.c chacha12.c
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCDIRS) -c $^ -o $@

clean:
	-rm *.o
	-rm *.a
