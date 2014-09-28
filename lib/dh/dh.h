/*
dh.h

Diffie-Hellman implementation

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../mp/libcrypt.h"
#include "../prnd/prnd.h"

/* Basic DH function. Can be used to compute both pow(g,x) mod p and
 * pow(g,x*y) mod p (as pow(pow(g,x) mod p,y) mod p).
 * g, x, and p and input parameters. gx has to be initialized and receives
 * the result value.
 */
void dh_gx(BigInt g, BigInt x, BigInt p, BigInt gx);

/* Assuming DH in a group (mod p) with subgroup of size q, check whether
 * p and q are prime and whether p = Nq+1. This function returns zero if
 * something is wrong and 1 if p and q are valid. prndp points to an
 * initialized pseudo random number generator.
 */
int dh_check_pq(BigInt p, BigInt q, prnd_t *prndp);

/* Assuming DH in a group (mod p) with subgroup of size q, check whether
 * q is prime and whether p = Nq+1. Other than not checking whether or not p
 * is prime, this function is the same as dh_check_pq.
 */
int dh_check_q(BigInt p, BigInt q, prnd_t *prndp);

/* Assuming DH in a group (mod p) with subgroup of size q, check whether
 * p = Nq+1.
 */
int dh_check_q_fast(BigInt p, BigInt q);

/* Check whether gx generates a subgroup of size q whithin the group
 * (mod p).
 */
int dh_check_gx(BigInt gx, BigInt p, BigInt q);

/* Generate a random generator of a subgroup of size q whithin the
 * group (mod p). prndp points to an initialized pseudo random number
 * generator. g has to be initialized and receives the result value.
 */
void dh_rnd_g(BigInt p, BigInt q, prnd_t *prndp, BigInt g);

/* Generate a random secret key for a subgroup of size q. prndp points to
 * an initialized pseudo random number generator. x has to be initialized
 * and receives the result value.
 */
void dh_rnd_x(BigInt q, prnd_t *prndp, BigInt x);

/*
 * $PchId: dh.h,v 1.1 2005/05/02 14:03:48 philip Exp $
 */
