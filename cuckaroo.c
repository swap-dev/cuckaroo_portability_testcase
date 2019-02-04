
#include <stdint.h>  
#include <stdio.h>
#include "blake2.h"  
#include <unistd.h>
#include <string.h>
#include "portable_endian.h"    // for htole32/64

typedef struct siphash_keys__
{
	uint64_t k0;
	uint64_t k1;
	uint64_t k2;
	uint64_t k3;
} siphash_keys;

static void setsipkeys(const char *keybuf,siphash_keys *keys) {
	keys->k0 = htole64(((uint64_t *)keybuf)[0]);
	keys->k1 = htole64(((uint64_t *)keybuf)[1]);
	keys->k2 = htole64(((uint64_t *)keybuf)[2]);
	keys->k3 = htole64(((uint64_t *)keybuf)[3]);
}
static void setheader(const char *header, const uint32_t headerlen, siphash_keys *keys) {
	char hdrkey[32];
	blake2b((void *)hdrkey, sizeof(hdrkey), (const void *)header, headerlen, 0, 0);
	setsipkeys(hdrkey,keys);
}


// Cuck(at)oo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2019 John Tromp
#define PROOFSIZE 42
#define EDGEBITS 29
#define EDGE_BLOCK_BITS 6
#define EDGE_BLOCK_SIZE (1 << EDGE_BLOCK_BITS)
#define EDGE_BLOCK_MASK (EDGE_BLOCK_SIZE - 1)
#define NEDGES ((uint32_t)1 << EDGEBITS)
#define EDGEMASK ((uint32_t)NEDGES - 1)
static uint64_t v0;
static uint64_t v1;
static uint64_t v2;
static uint64_t v3;
static uint64_t rotl(uint64_t x, uint64_t b) {
	return (x << b) | (x >> (64 - b));
}
static void sip_round() {
	v0 += v1; v2 += v3; v1 = rotl(v1,13);
	v3 = rotl(v3,16); v1 ^= v0; v3 ^= v2;
	v0 = rotl(v0,32); v2 += v1; v0 += v3;
	v1 = rotl(v1,17);   v3 = rotl(v3,21);
	v1 ^= v2; v3 ^= v0; v2 = rotl(v2,32);
}
static void hash24(const uint64_t nonce) {
	v3 ^= nonce;
	sip_round(); sip_round();
	v0 ^= nonce;
	v2 ^= 0xff;
	sip_round(); sip_round(); sip_round(); sip_round();
}
static uint64_t xor_lanes() {
	return (v0 ^ v1) ^ (v2  ^ v3);
}
static uint64_t sipblock(siphash_keys *keys, const uint32_t edge,uint64_t  *buf) {
	v0=keys->k0;
	v1=keys->k1;
	v2=keys->k2;
	v3=keys->k3;

	uint32_t edge0 = edge & ~EDGE_BLOCK_MASK;
	for (uint32_t i=0; i < EDGE_BLOCK_SIZE; i++) {
		hash24(edge0 + i);
		buf[i] = xor_lanes();
	}
	const uint64_t last = buf[EDGE_BLOCK_MASK];
	for (uint32_t i=0; i < EDGE_BLOCK_MASK; i++)
		buf[i] ^= last;
	return buf[edge & EDGE_BLOCK_MASK];
}
enum verify_code { POW_OK, POW_HEADER_LENGTH, POW_TOO_BIG, POW_TOO_SMALL, POW_NON_MATCHING, POW_BRANCH, POW_DEAD_END, POW_SHORT_CYCLE};
const char *errstr[] = { "OK", "wrong header length", "edge too big", "edges not ascending", "endpoints don't match up", "branch in cycle", "cycle dead ends", "cycle too short"};
int verify(uint32_t edges[PROOFSIZE], siphash_keys *keys) {
	uint32_t xor0 = 0, xor1 = 0;
	uint64_t sips[EDGE_BLOCK_SIZE];
	uint32_t uvs[2*PROOFSIZE];

	for (uint32_t n = 0; n < PROOFSIZE; n++) {
		if (edges[n] > EDGEMASK)
			return POW_TOO_BIG;
		if (n && edges[n] <= edges[n-1])
			return POW_TOO_SMALL;
		uint64_t edge = sipblock(keys, edges[n], sips);
		xor0 ^= uvs[2*n  ] = edge & EDGEMASK;
		xor1 ^= uvs[2*n+1] = (edge >> 32) & EDGEMASK;
		}
	if (xor0 | xor1)              // optional check for obviously bad proofs
		return POW_NON_MATCHING;
	uint32_t n = 0, i = 0, j;
	do {                        // follow cycle
		for (uint32_t k = j = i; (k = (k+2) % (2*PROOFSIZE)) != i; ) {
			if (uvs[k] == uvs[i]) { // find other edge endpoint identical to one at i
				if (j != i)           // already found one before
					return POW_BRANCH;
				j = k;
			}
		}
		if (j == i) return POW_DEAD_END;  // no matching endpoint
		i = j^1;
		n++;
	} while (i != 0);           // must cycle back to start or we would have found branch
	return n == PROOFSIZE ? POW_OK : POW_SHORT_CYCLE;
}

int main(int argc, char **argv) {

	char header[10];
	memset(header, 0, 10);
	
	header[1] = 2;
	header[9] = 12;

	siphash_keys keys;
	setheader(header,10,&keys);

	printf("k0 %llu\n",keys.k0);
	printf("k1 %llu\n",keys.k1);
	printf("k2 %llu\n",keys.k2);
	printf("k3 %llu\n",keys.k3);

	uint32_t edges[PROOFSIZE] = {3630647,22264576,26481684,36143584,40488771,56761690,75686903,91358206,105443927,133707559,142538312,144073846,154225649,166535986,185598250,215815903,224309845,224640377,224804206,262593054,281141248,284953652,293013797,299650808,358596672,370503515,392338062,404082256,413152628,414566961,424678135,426480708,437276687,452007991,463625388,469139392,473621789,487064831,498476194,523712905,526070495,527478662};

	printf("result: %s\n",errstr[verify(edges,&keys)]);
		
	unsigned char cyclehash[32];
	blake2b((void *)cyclehash, sizeof(cyclehash), (const void *)edges, sizeof(edges), 0, 0);
	for (int i=0; i<32; i++)
		printf("%02x", cyclehash[i]);
	printf("\n");

//hexHeader '0002'
//nonce     12
//Solution  376637 153bb00 1941414 22781e0 269cf43 3621d5a 482e3f7 57203fe 648f257 7f83727 87ef648 8966476 9314bf1 9ed2332 b10012a cdd16df d5eb255 d63bd79 d663d6e fa6da1e 10c1e000 10fc0c34 11770925 11dc4ef8 155fc040 16156f5b 17629a8e 1815ce50 18a03574 18b5ca31 195012f7 196b9444 1a10500f 1af11837 1ba25cac 1bf67fc0 1c3ae51d 1d0804ff 1db624a2 1f373989 1f5b32df 1f70af86
//cyclehash 852afb15e0f20dd003ca76d88488f6506d344f9c50bfc48a1d6cce3b484c1b50

}
