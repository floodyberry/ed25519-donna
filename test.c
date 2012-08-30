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

int main(int argc, const char *argv[]) {
	int i, res;
	ed25519_public_key pk;
	ed25519_signature sig;
	unsigned char forge[1024] = {'x'};
	uint64_t ticks, pkticks = maxticks, signticks = maxticks, openticks = maxticks;

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
	printf("success\n");

	for (i = 0; i < 2048; i++) {
		timeit(ed25519_publickey(dataset[0].sk, pk), pkticks)
		edassertequal(dataset[0].pk, pk, sizeof(pk), i, "public key didn't match");
		timeit(ed25519_sign((unsigned char *)dataset[0].m, 0, dataset[0].sk, pk, sig), signticks)
		edassertequal(dataset[0].sig, sig, sizeof(sig), i, "signature didn't match");
		timeit(res = ed25519_sign_open((unsigned char *)dataset[0].m, 0, pk, sig), openticks)
		edassert(!res, 0, "failed to open message");
	}
	printf("%.0f ticks/public key generation\n", (double)pkticks);
	printf("%.0f ticks/signature\n", (double)signticks);
	printf("%.0f ticks/signature verification\n", (double)openticks);
	return 0;
}