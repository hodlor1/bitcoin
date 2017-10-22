/*
     The MIT License (MIT)

    Copyright (c) 2013-2016 John Tromp

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/
#include "crypto/cuckoo.h"
#include "compat/endian.h"


#ifndef ROTL
#define ROTL(x,b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )
#endif 
#ifndef SIPROUND
#define SIPROUND \
  do { \
    v0 += v1; v2 += v3; v1 = ROTL(v1,13); \
    v3 = ROTL(v3,16); v1 ^= v0; v3 ^= v2; \
    v0 = ROTL(v0,32); v2 += v1; v0 += v3; \
    v1 = ROTL(v1,17);   v3 = ROTL(v3,21); \
    v1 ^= v2; v3 ^= v0; v2 = ROTL(v2,32); \
  } while(0)
#endif




uint64_t CCuckooCycleVerfier::siphash24(const cuckoo_cycle::siphash_keys *keys, const uint64_t nonce) {
  uint64_t v0 = keys->k0 ^ 0x736f6d6570736575ULL, v1 = keys->k1 ^ 0x646f72616e646f6dULL,
      v2 = keys->k0 ^ 0x6c7967656e657261ULL, v3 = keys->k1 ^ 0x7465646279746573ULL ^ nonce;
  SIPROUND; SIPROUND;
  v0 ^= nonce;
  v2 ^= 0xff;
  SIPROUND; SIPROUND; SIPROUND; SIPROUND;
  return (v0 ^ v1) ^ (v2  ^ v3);
}

void CCuckooCycleVerfier::siphash_setkeys(cuckoo_cycle::siphash_keys *keys, const unsigned char *keybuf) {
  keys->k0 = htole64(((uint64_t *)keybuf)[0]);
  keys->k1 = htole64(((uint64_t *)keybuf)[1]);
}

uint32_t CCuckooCycleVerfier::sipnode(cuckoo_cycle::siphash_keys *keys, uint32_t nonce, uint32_t uorv, uint32_t edgemask) {
	return (siphash24(keys, 2*nonce + uorv) & edgemask) << 1 | uorv;
}

cuckoo_cycle::cuckoo_verify_code CCuckooCycleVerfier::verify(uint32_t nonces[CUCKOO_CYCLE_PROOFSIZE], const unsigned char *buf, uint32_t edgebits) {

  uint32_t nedges = ((uint32_t)1 << edgebits);
  uint32_t edgemask =  ((uint32_t)nedges - 1);

  cuckoo_cycle::siphash_keys keys;
  siphash_setkeys(&keys, buf);
  uint32_t uvs[2*CUCKOO_CYCLE_PROOFSIZE];
  uint32_t xor0=0,xor1=0;
  for (uint32_t n = 0; n < CUCKOO_CYCLE_PROOFSIZE; n++) {
    if (nonces[n] > edgemask)
      return cuckoo_cycle::POW_TOO_BIG;
    if (n && nonces[n] <= nonces[n-1])
      return cuckoo_cycle::POW_TOO_SMALL;
	xor0 ^= uvs[2 * n] = CCuckooCycleVerfier::sipnode(&keys, nonces[n], 0, edgemask);
	xor1 ^= uvs[2 * n + 1] = CCuckooCycleVerfier::sipnode(&keys, nonces[n], 1, edgemask);
  }
  if (xor0|xor1)              // matching endpoints imply zero xors
    return cuckoo_cycle::POW_NON_MATCHING;
  uint32_t n = 0, i = 0, j;
  do {                        // follow cycle
    for (uint32_t k = j = i; (k = (k+2) % (2*CUCKOO_CYCLE_PROOFSIZE)) != i; ) {
      if (uvs[k] == uvs[i]) { // find other edge endpoint identical to one at i
        if (j != i)           // already found one before
          return cuckoo_cycle::POW_BRANCH;
        j = k;
      }
    }
    if (j == i) return cuckoo_cycle::POW_DEAD_END;  // no matching endpoint
    i = j^1;
    n++;
  } while (i != 0);           // must cycle back to start or we would have found branch
  return n == CUCKOO_CYCLE_PROOFSIZE ? cuckoo_cycle::POW_OK : cuckoo_cycle::POW_SHORT_CYCLE;
}
