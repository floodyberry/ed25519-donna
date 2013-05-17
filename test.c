/*
	Validate ed25519 implementation against the official test vectors from 
	http://ed25519.cr.yp.to/software.html
*/

#include <stdio.h>
#include <string.h>
#include "ed25519.h"

#include "test-ticks.h"

/* test data verification */
typedef struct test_data_t {
	unsigned char sk[32], pk[32], sig[64];
	const char *m;
} test_data;


test_data dataset[] = {
#include "regression.h"
};

/* result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)... 1024 times */
const curved25519_key curved25519_expected = {
	0xac,0xce,0x24,0xb1,0xd4,0xa2,0x36,0x21,0x15,0xe2,0x3e,0x84,0x3c,0x23,0x2b,0x5f,0x95,0x6c,0xc0,0x7b,0x95,0x82,0xd7,0x93,0xd5,0x19,0xb6,0xf1,0xfb,0x96,0xd6,0x04
};

void edassert(int check, int round, const char *failreason) {
	if (check)
		return;
	printf("round %d, %s\n", round, failreason);
	exit(1);
}

void edassertequal(const unsigned char *a, const unsigned char *b, size_t len, int round, const char *failreason) {
	size_t i;
	if (memcmp(a, b, len) == 0)
		return;
	printf("round %d, %s\n", round, failreason);
	printf("want: "); for (i = 0; i < len; i++) printf("%02x,", a[i]); printf("\n");
	printf("got : "); for (i = 0; i < len; i++) printf("%02x,", b[i]); printf("\n");
	printf("diff: "); for (i = 0; i < len; i++) if (a[i] ^ b[i]) printf("%02x,", a[i] ^ b[i]); else printf("  ,"); printf("\n\n");
	exit(1);
}

int main() {
	int i, res;
	ed25519_public_key pk;
	ed25519_signature sig;
	unsigned char forge[1024] = {'x'};
	curved25519_key csk[2] = {{255}};
	uint64_t ticks, pkticks = maxticks, signticks = maxticks, openticks = maxticks, curvedticks = maxticks;

	for (i = 0; i < 1024; i++) {
		ed25519_publickey(dataset[i].sk, pk);
		edassertequal(dataset[i].pk, pk, sizeof(pk), i, "public key didn't match");
		ed25519_sign((unsigned char *)dataset[i].m, i, dataset[i].sk, pk, sig);
		edassertequal(dataset[i].sig, sig, sizeof(sig), i, "signature didn't match");
		edassert(!ed25519_sign_open((unsigned char *)dataset[i].m, i, pk, sig), i, "failed to open message");

		memcpy(forge, dataset[i].m, i);
		if (i)
			forge[i - 1] += 1;

		edassert(ed25519_sign_open(forge, (i) ? i : 1, pk, sig), i, "opened forged message");
	}

	for (i = 0; i < 1024; i++)
		curved25519_scalarmult_basepoint(csk[(i & 1) ^ 1], csk[i & 1]);
	edassertequal(curved25519_expected, csk[0], sizeof(curved25519_key), 0, "curve25519 failed to generate correct value");

	printf("success\n");

	for (i = 0; i < 2048; i++) {
		timeit(ed25519_publickey(dataset[0].sk, pk), pkticks)
		edassertequal(dataset[0].pk, pk, sizeof(pk), i, "public key didn't match");
		timeit(ed25519_sign((unsigned char *)dataset[0].m, 0, dataset[0].sk, pk, sig), signticks)
		edassertequal(dataset[0].sig, sig, sizeof(sig), i, "signature didn't match");
		timeit(res = ed25519_sign_open((unsigned char *)dataset[0].m, 0, pk, sig), openticks)
		edassert(!res, 0, "failed to open message");
		timeit(curved25519_scalarmult_basepoint(csk[1], csk[0]), curvedticks);
	}
	printf("%.0f ticks/public key generation\n", (double)pkticks);
	printf("%.0f ticks/signature\n", (double)signticks);
	printf("%.0f ticks/signature verification\n", (double)openticks);
	printf("%.0f ticks/curve25519 basepoint scalarmult\n", (double)curvedticks);
	return 0;
}