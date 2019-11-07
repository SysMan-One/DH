#define	__MODULE__	"DHEXMPL"
#define	__IDENT__	"X.00-01"

#ifdef	__GNUC__
	#ident			__IDENT__
#endif

#pragma GCC diagnostic ignored  "-Wparentheses"
#pragma GCC diagnostic ignored	"-Wdiscarded-qualifiers"
#pragma GCC diagnostic ignored	"-Wmissing-braces"
#pragma GCC diagnostic ignored	"-Wfdollars-in-identifiers"

/*
**++
**
**  FACILITY:  An example of Anonimous Diffie-Hellman
**
**  ABSTRACT:  An example of building encrypted channel by using keys' interchange base on Anonimpus Diffie-Hellman
**	alghorytm
**
**  DESCRIPTION:
**
**
**  DESIGN ISSUE:
**
** Сервер                                                 Клиент
------------------------------------------------------------------------------------------------
Генерация p, q (не используется), g


PrivKserver - случайное число заданной длины (160 битов, то есть достаточно длинное)
PubKserver = f(PrivKserver, p, g)
	PubKserver = (g^PrivKserver) mod p



				 ----->>>> p, g, PubKserver
------------------------------------------------------------------------------
						  PrivKclient - как-то генерируется
						  PubKclient = f (p, g, PrivKclient)
						  PubKclient = (g^PrivKclient) mod p

						  SesssionKey = f(PubKserver, PrivKclient)
						  SesssionKey = PubKserver ^ PrivKclient

				<<<<----- PubKclient
------------------------------------------------------------------------------------------------
SesssionKey = f(PrivKserver, PubKclient)
SesssionKey = PubKclient ^ PrivKserver
------------------------------------------------------------------------------------------------
				 обмен данными
				     GOST89
**
**  AUTHORS: Ruslan R. Laishev (RRL)
**
**  CREATION DATE: 05-NOV-2019
**
**  USAGE:
**
**  MODIFICATION HISTORY:
**
*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>


#include	<openssl/dh.h>
#include	<openssl/bn.h>

#ifdef	__x86_64__
	#define	__ARCH__NAME__	"x86_64"
#else
#ifdef	__i386
	#define	__ARCH__NAME__	"i386"
#endif
#endif

#ifdef	_WIN64
	#define	__ARCH__NAME__	"Win64"
#elifdef _WIN32
	#define	__ARCH__NAME__	"Win32"
#endif


/*
* Defines and includes for enable extend trace and logging
*/
#define		__FAC__	"DHEXMPL"
#define		__TFAC__ __FAC__ ": "
#include	"utility_routines.h"

#define $SHOW_PTR(var)			$SHOW_PARM(var, var, "%p")
#define $SHOW_STR(var)			$SHOW_PARM(var, (var ? var : "UNDEF(NULL)"), "'%s'")
#define $SHOW_INT(var)			$SHOW_PARM(var, ((int) var), "%d")
#define $SHOW_UINT(var)			$SHOW_PARM(var, ((unsigned) var), "%u")
#define $SHOW_ULL(var)			$SHOW_PARM(var, ((unsigned long long) var), "%llu")
#define $SHOW_UNSIGNED(var)		$SHOW_PARM(var, var, "0x%08x")
#define $SHOW_BOOL(var)			$SHOW_PARM(var, (var ? "ENABLED(TRUE)" : "DISABLED(FALSE)"), "%s");


typedef struct	__rnd_seed__
{
	struct timespec	ts;
	pid_t		pid;
	struct timespec	ts2;
} RND_SEED;






#define	DH$SZ_PRIME	(20*8)		/* 640 bits	*/

static	int	__dh_server_init	(
			BIGNUM	*a,
			BIGNUM	*p,
			BIGNUM	*g,
			BIGNUM	*A
				)
{
int	status = STS$K_ERROR, rc, count;
BIGNUM	*q, *h, *bn_res, *bn_gexp, *bn_minusone, *bn_one;
BN_CTX	*bn_ctx; /* used internally by the bignum lib */
RND_SEED	rnd_seed;
char	errbuf[512];

	/* Initialize context for random seeding */
	if ( rc = clock_gettime(CLOCK_MONOTONIC, &rnd_seed.ts) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", rc, errno);

	if ( rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &rnd_seed.ts2) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", status, errno);

	rnd_seed.pid = getpid();

	/* Performs random seeding or BN_generate_prime_ex may fail */
	rc = RAND_seed(&rnd_seed, sizeof (rnd_seed) );

	bn_ctx = BN_CTX_new();

	/* Allocate area for bignumbers */
	q = BN_new();
	h = BN_new();
	bn_res = BN_new();
	bn_gexp = BN_new();
	bn_minusone = BN_new();	BN_set_word (bn_minusone, -1);
	bn_one = BN_new();	BN_set_word (bn_one, 1);

	/* Generate p and g ... */
	for (count = 0; ++count; )
		{
		// Calculate "p" = 2q + 1
		if ( !(status = BN_generate_prime_ex (q, DH$SZ_PRIME, 1 /* safe */, NULL, NULL, NULL)) )
			{
			ERR_print_errors_fp(stdout);
			break;
			}


		//$TRACE("q : %s", BN_bn2hex (q));
		BN_lshift1(p, q);	// p = p * 2
		BN_add(p, p, bn_one);	// p = p - 1
		//$TRACE("p : %s", BN_bn2hex (p));

		// 1: gExp = (p - 1) / q
		// 2: h =>   1 < h < (p - 1)
		// 3: g = h^gExp mod p
		BN_sub (bn_res, p, bn_minusone);				// bn_res = p - 1
		BN_div(bn_gexp, NULL, bn_res /*bn_res = p - 1 */, q, bn_ctx);	// 1: gExp = (p - 1) / q
		BN_pseudo_rand_range(h, bn_res /*bn_res = p - 1 */);		// 2: h =>   1 < h < (p - 1)
		BN_mod_exp(g, h, bn_gexp, p, bn_ctx);				// 3: g = h^gExp mod p

		BN_mod_exp(bn_res, g, q, p, bn_ctx);				// g^q mod p = 1, or it should

		if ( (status = (!BN_is_one (bn_res))) )
			break;
		}

	/* Generate private key random prime ... */
	if ( !(status = BN_generate_prime_ex (a, DH$SZ_PRIME, 1 /* safe */, NULL, NULL, NULL)) )
		ERR_print_errors_fp(stdout);

	/* Compute publick key as : A("publick key") = g ^ a mod p */
	BN_mod_exp(A, g, a, p, bn_ctx);


	/* Release has been allocated resource unconditionaly */
	BN_CTX_free(bn_ctx);

	BN_free(h);
	BN_free(bn_res);
	BN_free(bn_gexp);
	BN_free(bn_minusone);
	BN_free(bn_one);

	return	status;
}






static	int	__dh_client_init	(
			BIGNUM	*b,
			BIGNUM	*p,
			BIGNUM	*g,
			BIGNUM	*B
				)
{
int	status = STS$K_ERROR, rc;
BN_CTX	*bn_ctx; /* used internally by the bignum lib */
RND_SEED	rnd_seed;
char	errbuf[512];

	/* Initialize context for random seeding */
	if ( rc = clock_gettime(CLOCK_MONOTONIC, &rnd_seed.ts) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", rc, errno);

	if ( rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &rnd_seed.ts2) )
		return	$LOG(STS$K_ERROR, "clock_gettime()->%d, errno=%d", status, errno);

	rnd_seed.pid = getpid();

	/* Performs random seeding or BN_generate_prime_ex may fail */
	RAND_seed(&rnd_seed, sizeof (rnd_seed) );


	/* Generate private key random prime ... */
	if ( !(status = BN_generate_prime_ex (b, DH$SZ_PRIME, 1 /* safe */, NULL, NULL, NULL)) )
		ERR_print_errors_fp(stdout);


	/* Compute publick key as : A("publick key") = g ^ a mod p */
	bn_ctx = BN_CTX_new();
	BN_mod_exp(B, g, b, p, bn_ctx);
	BN_CTX_free(bn_ctx);

	return	status;
}


static	int	__dh_session_key(
			BIGNUM	*pubk,
			BIGNUM	*privk,
			BIGNUM	*p,
			BIGNUM	*skey
				)
{
int	status = STS$K_ERROR, rc;
BN_CTX	*bn_ctx; /* used internally by the bignum lib */

	/* Compute session key as: Session Key = PublickKey ^ PrivateKey mod p */
	bn_ctx = BN_CTX_new();
	BN_mod_exp(skey, pubk, privk, p, bn_ctx);
	BN_CTX_free(bn_ctx);

}






int	main	(int argc, char **argv)
{
int	status, rc;
char	errbuf[512];
BIGNUM	*cprivk, *cpubk, *sprivk, *spubk, *sskey, *cskey, *p, *g;
BN_CTX	*bn_ctx; /* used internally by the bignum lib */

	$LOG(STS$K_INFO, "Server context initialization ...");

	p = BN_new();
	g = BN_new();
	sprivk = BN_new();
	spubk = BN_new();

	__dh_server_init(sprivk, p, g, spubk);

	$LOG(STS$K_INFO, "Public p             : %s", BN_bn2hex (p));
	$LOG(STS$K_INFO, "Public g             : %s", BN_bn2hex (g));

	$LOG(STS$K_INFO, "Server DH private key: %s", BN_bn2hex (sprivk));
	$LOG(STS$K_INFO, "Server DH public key : %s", BN_bn2hex (spubk));


	/*
	 * Send to client: p, g, Server's publick key
	 *  .....
	 */


	/* Generate client's keys  with has been given from server: A  (erver's public key), p, g */
	$LOG(STS$K_INFO, "Client context initialization, input data (has been gotten from server) :");
	$LOG(STS$K_INFO, "\tPublic p             : %s", BN_bn2hex (p));
	$LOG(STS$K_INFO, "\tPublic g             : %s", BN_bn2hex (g));
	$LOG(STS$K_INFO, "\tServer DH public key : %s", BN_bn2hex (spubk));

	cprivk = BN_new();
	cpubk = BN_new();

	__dh_client_init(cprivk, p, g, cpubk);

	$LOG(STS$K_INFO, "Client DH private key: %s", BN_bn2hex (sprivk));
	$LOG(STS$K_INFO, "Client DH public key : %s", BN_bn2hex (spubk));


	/* Compute Session key at server and client sides */
	$LOG(STS$K_INFO, "Session keys generation ...");

	sskey = BN_new();
	cskey = BN_new();


	__dh_session_key (cpubk, sprivk, p, sskey);
	$LOG(STS$K_INFO, "Server DH session key: %s", BN_bn2hex (sskey));

	__dh_session_key (spubk, cprivk, p, cskey);
	$LOG(STS$K_INFO, "Client DH session key: %s", BN_bn2hex (cskey));
}
