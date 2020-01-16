# SPHINCS with short-time state

This is an implementation of SPHINCS batch signing as described in my
yet-to-be-published master's thesis.
There are multiple differences to
the [SPHINCS signature scheme](https://sphincs.cr.yp.to/index.html) published in [[1]](#1):

 - To protect against multi-target attacks, all hash calls are seeded with bit
   masks. In classic SPHINCS, these bit masks were included in the private key.
   Here, the bit masks are generated ad-hoc with an addressing scheme modeled
   after XMSS-T [[2]](#2).

 - This version of SPHINCS comes with an extended API to expose the batch
   signing capabilities. The extended API is explained below.

## Batch signing API

This version of SPHINCS offers an API for faster signatures. To use this API,
you will need to initialize a so-called short-time state first, by calling
`crypto_sts_init`. That short-time state can then be used to sign a limited
number of messages, by calling `crypto_sts_sign`.

 - Initialize a short-time state:
   ```
   int crypto_sts_init(unsigned char *short_time_state,
                       const unsigned char *secret_key, long long subtree_idx);
   ```

 - Sign a message using the short-time state:
   ```
   int crypto_sts_sign(unsigned char *signature, unsigned long long *signature_length,
                       const unsigned char *message, unsigned long long message_length,
                       unsigned char *short_time_state
                       const unsigned char *secret_key);
   ```

Finally, there is a function to query how many more messages can be signed with
a given short-time state. Once the signing capacity of a short-time state is
exhausted, you will need to generate a new short-time state.

 - Query the number of messages that can be signed with the given short-time state:
   ```
   long long crypto_sts_remaining_uses(unsigned char *short_time_state);
   ```


In addition to that, the traditional API is also supported:

 - Create a keypair:
   ```
   int crypto_sign_keypair(unsigned char *public_key, unsigned char *secret_key);
   ```

 - Sign a message:
   ```
   int crypto_sign(unsigned char *signature, unsigned long long *signature_length,
                   const unsigned char *message, unsigned long long message_length,
                   const unsigned char *secretkey);
   ```

 - Verify a signature:
   ```
   int crypto_sign_open(unsigned char *message, unsigned long long *message_length,
                        const unsigned char *signature, unsigned long long signature_length,
                        const unsigned char *public_key);
   ```

## Variants

This repository essentially offers three variants of SPHINCS:

 - **Classic SPHINCS**, without batch signing.
 - **Sequential batch signing**, which speeds up signatures by signing messages
   with sequential leaf nodes of the hypertree, and caching the parts of the
   signature that is shared between them.
 - **Subtree batch signing**, which speeds up signatures by creating a subtree,
   and signing the root of the subtree with a HORST keypair of the hypertree.
   The individual messages are then signed with WOTS key pairs, the public keys
   of which form the leaf nodes of the subtree.

All variants feature smaller secret key sizes.

The Makefile in `src` contains recipes to build libraries for each variant:

 - `libsphincs.a` for classic SPHINCS,
 - `libsphincs_sequential.a` for sequential batch signing,
 - `libsphincs_subtree.a` for subtree batch signing.

## Example usage

The source directory contains three example files, one for each variant:

 - `example.c` for classic SPHINCS,
 - `example_sequential.c` for sequential batch signing,
 - `example_subtree.c` for subtree batch signing.

Build and run them with e.g. `make example_sequential && ./example_sequential`.

## Tests

Run `make test` to run the tests.

## Benchmarks

There is primitive benchmarking code to measure some cycles, which you can run
with `make bench`. It will print key sizes, signature sizes, STS sizes, and
cycle counts for the three variants for a single signature.

Note that this software is not optimized, and significantly slower than the
vectorized implementation of SPHINCS.

Example output, on Intel i5-4690K:

```
./bench_sphincs_sign
Benchmark SPHINCS signatures
   crypto_secretkeybytes:                       96 B
   crypto_publickeybytes:                       64 B
            crypto_bytes:                    41000 B
                 Keypair: ----+----+----+----+----+--              1.72 * 2^27 cycles
     Sign, 32 signatures: ----+----+----+----+----+----+----+-     1.60 * 2^36 cycles
 Sign, avg per signature: ----+----+----+----+----+----+-          1.60 * 2^31 cycles
                  Verify: ----+----+----+----+----+                1.36 * 2^25 cycles
          Elapsed cycles: ----+----+----+----+----+----+----+-     1.61 * 2^36 cycles
./bench_subtree_batch_sign
Benchmark SPHINCS subtree batch signatures
   crypto_secretkeybytes:                       96 B
   crypto_publickeybytes:                       64 B
        crypto_sts_bytes:                    36233 B
            crypto_bytes:                    37416 B
                 Keypair: ----+----+----+----+----+--              1.74 * 2^27 cycles
                STS init: ----+----+----+----+----+----+-          1.60 * 2^31 cycles
     Sign, 32 signatures: ----+----+----+----+----+--              1.69 * 2^27 cycles
 Sign, avg per signature: ----+----+----+----+--                   1.69 * 2^22 cycles
                  Verify: ----+----+----+----+----+                1.48 * 2^25 cycles
          Elapsed cycles: ----+----+----+----+----+----+-          1.83 * 2^31 cycles
./bench_sequential_batch_sign
Benchmark SPHINCS sequential batch signatures
   crypto_secretkeybytes:                       96 B
   crypto_publickeybytes:                       64 B
        crypto_sts_bytes:                    26376 B
            crypto_bytes:                    41000 B
                 Keypair: ----+----+----+----+----+--              1.72 * 2^27 cycles
                STS init: ----+----+----+----+----+----+-          1.30 * 2^31 cycles
     Sign, 32 signatures: ----+----+----+----+----+----+----       1.21 * 2^34 cycles
 Sign, avg per signature: ----+----+----+----+----+----            1.21 * 2^29 cycles
                  Verify: ----+----+----+----+----+                1.38 * 2^25 cycles
          Elapsed cycles: ----+----+----+----+----+----+----       1.39 * 2^34 cycles
```

## Caveats of a short-time state

SPHINCS is a stateless signature scheme: Once a keypair is produced,
only that keypair is necessary to sign new messages. This behaviour is in line
with commonly used signature schemes like RSA, DSA and ECDSA.

However, there are many *stateful* hash-based signature schemes, like the
classic Merkle Signature Scheme, and its variations XMSS, XMSS-T, CMSS, and
others. Key pairs in these schemes are associated with a fixed number of
one-time signature (OTS) key pairs (e.g. Winternitz OTS [[3, Section 5]](#3)).
As the name suggests, each OTS key pair can only be used for a single
signature. Re-using the same OTS key pair has the potential to break the
scheme, and can allow an attacker to forge signatures. Because of that, new
signatures depends on previously signed messages, since the signer needs to
distinguish used from unused OTS key pairs.

With stateful signatures, the data that contains the stateful information (the
_state_) has to be handled with care. If it is restored from a backup, a VM
snapshot, or shared between processes without proper synchronization, then
there is a risk that used key material is re-used, potentially breaking the
scheme.

The batch signing variants of SPHINCS in this repository use a short-time state
to speed up signatures. Any precautions that apply to stateful signature
schemes also apply to this short-time state. However, no additional precautions
have to be taken when handling the keypair.


---

This code is based on the [SUPERCOP](https://bench.cr.yp.to/supercop.html)
implementation of SPHINCS, written by
Daniel J. Bernstein,
Daira Hopwood,
Andreas Hülsing,
Tanja Lange,
Ruben Niederhagen,
Louiza Papachristodoulou,
Peter Schwabe, and
Zooko Wilcox O'Hearn

---

<span id="1">[1]</span>: Daniel J. Bernstein, Daira Hopwood, Andreas Hülsing,
Tanja Lange, Ruben Niederhagen, Louiza Papachristodoulou, Michael Schneider,
Peter Schwabe, Zooko Wilcox-O'Hearn. _"SPHINCS: practical stateless hash-based
signatures."_ Pages 368–397 in Advances in cryptology—EUROCRYPT 2015—34th
annual international conference on the theory and applications of cryptographic
techniques, Sofia, Bulgaria, April 26–30, 2015, proceedings, part I, edited by
Elisabeth Oswald, Marc Fischlin. Lecture Notes in Computer Science 9056,
Springer, 2015. ISBN 978-3-662-46799-2. Date: 2015.02.02.
([PDF](https://sphincs.cr.yp.to/sphincs-20141001.pdf))

<span id="2">[2]</span>: Andreas Hülsing, Joost Rijneveld, and Fang Song.
_Mitigating multi-target attacks in hash-based signatures._ In Public-Key
Cryptography–PKC 2016, pages 387–416. Springer, 2016.
([PDF](http://eprint.iacr.org/2015/1256.pdf))

<span id="2">[2]</span>: Ralph Merkle. A certified digital signature. In
Advances in Cryptol- ogy—CRYPTO’89 Proceedings, pages 218–238. Springer, 1990.
([PDF](http://www.merkle.com/papers/Certified1979.pdf))
