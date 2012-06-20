[ed25519](http://ed25519.cr.yp.to/) is an 
[Elliptic Curve Digital Signature Algortithm](http://en.wikipedia.org/wiki/Elliptic_Curve_DSA), 
developed by [Dan Bernstein](http://cr.yp.to/djb.html), 
[Niels Duif](http://www.nielsduif.nl/), 
[Tanja Lange](http://hyperelliptic.org/tanja), 
[Peter Schwabe](http://www.cryptojedi.org/users/peter/), 
and [Bo-Yin Yang](http://www.iis.sinica.edu.tw/pages/byyang/).

This project provides performant, portable 32-bit & 64-bit implementations. All implementations are 
of course constant time in regard to secret data.

#### Performance (On an E5200 @ 2.5ghz)

<table>
<thead><tr><th>Implementation</th><th>Sign Cycles</th><th>gcc</th><th>icc</th><th>clang</th><th>Verify Cycles</th><th>gcc</th><th>icc</th><th>clang</th></tr></thead>
<tbody>
<tr><td>ed25519-donna 32bit</td><td></td><td>603k</td><td>373k</td><td>451k</td><td></td><td>1782k</td><td>1130k</td><td>1374k</td></tr>
<tr><td>ed25519-donna 64bit</td><td></td><td>132k</td><td>129k</td><td>140k</td><td></td><td>382k</td><td>391k</td><td>413k</td></tr>
<tr><td>ed25519-donna-sse2 32bit</td><td></td><td>179k</td><td>155k</td><td>184k</td><td></td><td>395k</td><td>378k</td><td>490k</td></tr>
<tr><td>ed25519-donna-sse2 64bit</td><td></td><td>122k</td><td>114k</td><td>128k</td><td></td><td>372k</td><td>352k</td><td>412k</td></tr>
</tbody>
</table>

SSE2 performance may be less impressive on AMD & older CPUs with slower SSE ops!

#### Compilation

No configuration is needed. 

##### 32-bit

	gcc ed25519.c -m32 -O3 -c

##### 64-bit

	gcc ed25519.c -m64 -O3 -c

##### SSE2

	gcc ed25519.c -m32 -O3 -c -DED25519_SSE2
	gcc ed25519.c -m64 -O3 -c -DED25519_SSE2

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