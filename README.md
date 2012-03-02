[ed25519](http://ed25519.cr.yp.to/) is an 
[Elliptic Curve Digital Signature Algortithm](http://en.wikipedia.org/wiki/Elliptic_Curve_DSA), 
developed by [Dan Bernstein](http://cr.yp.to/djb.html), 
[Niels Duif](http://www.nielsduif.nl/), 
[Tanja Lange](http://hyperelliptic.org/tanja), 
[Peter Schwabe](http://www.cryptojedi.org/users/peter/), 
and [Bo-Yin Yang](http://www.iis.sinica.edu.tw/pages/byyang/).

This project provides performant, portable 32-bit & 64-bit implementations.

#### Performance (On an E5200 @ 2.5ghz)

...

#### Compilation

No configuration is needed. 

##### 32-bit

	gcc ed25519.c -m32 -O3 -c

##### 64-bit

	gcc ed25519.c -m64 -O3 -c

##### SSE2

	gcc ed25519.c -m32 -O3 -c -DED25519_SSE2

clang and icc are also supported


#### Usage

To use the code, link against "**ed25519.o** -lssl" and:

	#include "ed25519.h"

To generate a private key, simply generate 32 bytes from a secure
cryptographic source:

	ed25519_secret_key sk;
	randombytes(sk, sizeof(ed25519_secret_key));

To generate a public key:

	ed25519_public_key pk;
	ed25519_public_key(sk, pk);

To sign a message:

	ed25519_signature sig;
	ed25519_sign(message, message_len, sk, pk, signature);

To verify a signature:

	int valid = ed25519_sign_open(message, message_len, pk, signature) == 0;

Unlike the [SUPERCOP](http://bench.cr.yp.to/supercop.html) version, signatures are
not appended to messages, and there is no need for padding in front of messages. 
Additionally, the secret key does not contain a copy of the public key, so it is 
32 bytes instead of 64 bytes, and the public key must be provided to the signing
function.

#### Papers

[Available on the Ed25519 website](http://ed25519.cr.yp.to/papers.html)