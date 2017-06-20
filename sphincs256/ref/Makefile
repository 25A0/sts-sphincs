TESTS := $(shell find . -type f -name "test_*.c" | sed -e 's/.c$$/.o/g')
BENCHS := $(shell find . -type f -name "bench_*.c" | sed -e 's/.c$$/.o/g')

BOLD := $(shell tput bold)
RED := $(shell tput setaf 1)
NORMAL := $(shell tput sgr0)

all: libsphincs.a ${TESTS}

INCDIRS=-I. -I./include
CFLAGS=-g -Wall

.PHONY = clean test bench

libsphincs.a: sign.o horst.o zerobytes.o randombytes.o hash.o wots.o blake256.o blake512.o permute.o prg.o chacha12.o hash_address.o tree.o
	$(AR) -ar cr $@ $^

libsphincs_sequential.a: sign.o sequential_batch_sign.o horst.o zerobytes.o randombytes.o hash.o wots.o blake256.o blake512.o permute.o prg.o chacha12.o hash_address.o tree.o
	$(AR) -ar cr $@ $^

libsphincs_subtree.a: sign.o subtree_batch_sign.o horst.o zerobytes.o randombytes.o hash.o wots.o blake256.o blake512.o permute.o prg.o chacha12.o hash_address.o tree.o
	$(AR) -ar cr $@ $^

test_hash_addr.o: testutils.o test_hash_addr.c hash_address.o randombytes.o
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_chacha12.o: testutils.o test_chacha12.c chacha12.o randombytes.o
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_wots.o: testutils.o test_wots.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_tree.o: testutils.o test_tree.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_sphincs.o: testutils.o test_sphincs.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_sequential_batch_sign.o: testutils.o test_sequential_batch_sign.c libsphincs_sequential.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

bench_sequential_batch_sign.o: testutils.o bench_sequential_batch_sign.c libsphincs_sequential.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

bench_sphincs_sign.o: testutils.o bench_sphincs_sign.c libsphincs.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

bench_subtree_batch_sign.o: testutils.o bench_subtree_batch_sign.c libsphincs_subtree.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

test_subtree_batch_sign.o: testutils.o test_subtree_batch_sign.c libsphincs_subtree.a
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

bench_speed.o: testutils.o bench_speed.c libsphincs.a
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

bench: ${BENCHS}
	time -p sh -c "./bench_speed.o 1 10"
	time -p sh -c "./bench_speed.o 2 10"
