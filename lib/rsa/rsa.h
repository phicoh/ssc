/*
rsa.h

RSA signatures, key generation

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../mp/libcrypt.h"
#include "../prnd/prnd.h"
#include "../sha2/sha2.h"

#define RSA_PUBEXP_SIGN		3	/* Public exponent for signing */
#define RSA_PUBEXP_ENCRYPT	5	/* Public exponent for encryption */

#define RSA_HASH_LEN		SHA256_DIGEST_LENGTH

/* Generate a new RSA public/private key pair. bits specifies the required
 * size of the public key in bits. prndp should point to an initialized 
 * pseudo random number generator. n and p are output parameters and should
 * be initialized before calling this function. n receives the resulting
 * public key. p receives one of the two factors of the public key.
 */
void rsa_rnd_key(int bits, prnd_t *prndp, BigInt n, BigInt p);

/* Sign an SHA-2 hash value with an private key. The private key is passed as
 * the public key and one of the factors of the public key. s receives the
 * resulting signature and should be initialized before calling this function.
 */
void rsa_sign(unsigned char hash[RSA_HASH_LEN], BigInt n, BigInt p, BigInt s);

/* Verify that a value s is a valid signature for a SHA-2 hash and public
 * key n.
 */
int rsa_verify(unsigned char hash[RSA_HASH_LEN], BigInt s, BigInt n);

/*
 * $PchId: rsa.h,v 1.1 2005/05/02 15:10:41 philip Exp $
 */

/*
 * $PchId: rsa.h,v 1.1 2005/05/02 15:10:41 philip Exp $
 */
