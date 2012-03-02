/*
	Validate ed25519 implementation against the official test vectors from 
	http://ed25519.cr.yp.to/software.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ed25519.h"

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
	test_data *t = dataset;
	int i;
	ed25519_public_key pk;
	ed25519_signature sig;
	unsigned char forge[1024] = {'x'};

	for (i = 0; i < 1024; i++, t++) {
		ed25519_publickey(t->sk, pk);
		ed25519_sign((unsigned char *)t->m, i, t->sk, pk, sig);
		edassert(!ed25519_sign_open((unsigned char *)t->m, i, pk, sig), i, "failed to open message");
		
		memcpy(forge, t->m, i);
		if (i)
			forge[i - 1] += 1;

		edassert(ed25519_sign_open(forge, (i) ? i : 1, pk, sig), i, "opened forged message");
		edassertequal(t->pk, pk, sizeof(pk), i, "public key didn't match");
		edassertequal(t->sig, sig, sizeof(sig), i, "signature didn't match");
	}
	printf("pass\n");
	return 0;
}