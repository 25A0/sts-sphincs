TESTS := $(shell find . -type f -name "test_*.c" | sed -e 's/.c$$//g')
BENCHS := $(shell find . -type f -name "bench_*.c" | sed -e 's/.c$$//g')

BOLD := $(shell tput bold)
RED := $(shell tput setaf 1)
NORMAL := $(shell tput sgr0)

all: libsphincs.a ${TESTS}

INCDIRS=-I. -I./include
CFLAGS=-g -Wall

.PHONY = clean test bench

SPHINCS := horst.o zerobytes.o randombytes.o hash.o wots.o blake256.o	\
           blake512.o permute.o prg.o chacha12.o hash_address.o tree.o

# This Makefile can compile three different libraries. libsphincs is classic
# SPHINCS, libsphincs_sequential uses sequential batch signing, and
# libsphincs_subtree uses subtree batch signing.
libsphincs.a: sign.o ${SPHINCS}
	$(AR) cr $@ $^

libsphincs_sequential.a: sequential_batch_sign.o entropy.o ${SPHINCS}
	$(AR) cr $@ $^

libsphincs_subtree.a: subtree_batch_sign.o ${SPHINCS}
	$(AR) cr $@ $^

# These next lines define on which SPHINCS library the various tests and
# benchmarks depend.
test_horst test_wots test_tree test_sphincs bench_sphincs_sign bench_speed: libsphincs.a

test_sequential_batch_sign bench_sequential_batch_sign: libsphincs_sequential.a

bench_subtree_batch_sign test_subtree_batch_sign: libsphincs_subtree.a

test_hash_addr: hash_address.o randombytes.o

test_chacha12: chacha12.o randombytes.o

# All tests and benchmarks need the object file of the same name, as well as
# testutils.o
.SECONDEXPANSION:
${BENCHS}: benchutils.o $$@.o
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

${TESTS}: testutils.o $$@.o
	$(CC) $(CFLAGS) $(INCDIRS) $^ -o $@

example_subtree:    example_subtree.c libsphincs_subtree.a
example_sequential: example_sequential.c libsphincs_sequential.a
example:            example.c libsphincs.a

%.o: %.c
	$(CC) $(CFLAGS) $(INCDIRS) -c $^ -o $@

clean:
	-rm *.o
	-rm *.a

# This recipe runs all tests
test: ${TESTS}
	-@for test in ${TESTS}; do \
		echo $${test}; \
		./$${test} || echo "${BOLD}$${test} ${RED}FAILED${NORMAL}"; \
	done; true

# This recipe runs all benchmarks
bench: ${BENCHS}
	-@for bench in ${BENCHS}; do \
		echo $${bench}; \
		./$${bench} || echo "${BOLD}$${bench} ${RED}FAILED${NORMAL}"; \
	done; true
