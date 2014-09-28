#include <stdlib.h>

#include "../mp/libcrypt.h"
#include "../rndnum/rndnum.h"
#include "../prime/rndprime.h"
#include "dh.h"

static void usage(void);

int main(int argc, char *argv[])
{
	int i;
	char *len_str, *check;
	unsigned len;
	BigInt p, q, g;
	prnd_t prnd;

	if (argc != 2)
		usage();
	len_str= argv[1];

	len= strtoul(len_str, &check, 10);
	if (check[0] != '\0')
	{
		fprintf(stderr, "bad value '%s'\n", len_str);
		exit(1);
	}
	if (len < 300)
	{
		fprintf(stderr, "bad len %d, should be at least 300\n",
			len);
		exit(1);
	}

	prnd_init(&prnd, NULL, 0);

	q= bigInit(0);
	rnd_prime3(256, &prnd, q);

	p= bigInit(0);
	rnd_sg_prime4(len, q, &prnd, p);

	g= bigInit(0);
	dh_rnd_g(p, q, &prnd, g);

	printf("modulus = ");
	bigprint(p);

	printf("sub-group = ");
	bigprint(q);

	printf("g = "); bigprint(g);

	return 0;
}

static void usage(void)
{;
	fprintf(stderr, "Usage: dhgen <modulus-lenght>\n");
	exit(1);
}
