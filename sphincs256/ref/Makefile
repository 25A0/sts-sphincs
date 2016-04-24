
all: libsphincs.a test_chacha12.o test_sphincs.o

INCDIRS=-I. -I./include

libsphincs.a: sign.o horst.o zerobytes.o randombytes.o hash.o wots.o blake256.o blake512.o permute.o prg.o chacha12.o
	$(AR) -ar cr $@ $^

test_chacha12.o: test_chacha12.c chacha12.o
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_sphincs.o: test_sphincs.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCDIRS) -c $^ -o $@

clean:
	-rm *.o
	-rm *.a
