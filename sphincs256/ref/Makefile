TESTS := $(shell find . -type f -name "test_*.c" | sed -e 's/.c$$/.o/g')

BOLD := $(shell tput bold)
RED := $(shell tput setaf 1)
NORMAL := $(shell tput sgr0)

all: libsphincs.a ${TESTS}

INCDIRS=-I. -I./include
CFLAGS=-g -Wall

libsphincs.a: sign.o horst.o zerobytes.o randombytes.o hash.o wots.o blake256.o blake512.o permute.o prg.o chacha12.o hash_address.o tree.o
	$(AR) -ar cr $@ $^

test_chacha12.o: testutils.o test_chacha12.c chacha12.o
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_wots.o: testutils.o test_wots.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_sphincs.o: testutils.o test_sphincs.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_horst.o: testutils.o test_horst.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCDIRS) -c $^ -o $@

clean:
	-rm *.o
	-rm *.a

test: ${TESTS}
	-@for test in ${TESTS}; do \
		echo $${test}; \
		./$${test} || echo "${BOLD}$${test} ${RED}FAILED${NORMAL}"; \
	done; true

