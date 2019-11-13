#define	__MODULE__	"DHEXMPL"
#define	__IDENT__	"X.00-03"

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
**  ABSTRACT:  An example of building encrypted channel by using keys' interchange base on Anonymous Diffie-Hellman
**	alghorytm
**
**  DESCRIPTION: Just a demonatration of using OpenSSL API BN's routines to implement Diffie-Hellman keys exchange.
**
**
**  DESIGN ISSUE:
**
**	General schema of Diffie-Hellman keys exchange
**
**	Сервер                                                 Клиент
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
**
**
**  AUTHORS: Ruslan (The BadAss SysMan) Laishev at Security Code
**
**  CREATION DATE: 05-NOV-2019
**
**  BUILD:
**	gcc  -o DH-example DH-example.c utility_routines.c avproto.c gost89.c -lssl -lcrypto
**
**  USAGE:
**	./DH-example<ENTER>
**
**
**
**  MODIFICATION HISTORY:
**
**	 7-NOV-2019	RRL	X.00-02 : Increased keys size up to 256 bits;
**				improved output of final information for session keys.
**
**	13-NOV-2019	RRL	X.00-03 : Added client and server threads to demonstrate DHKEXC
**				in client server interoperation.
**
*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>
#include	<poll.h>

#include	<pthread.h>
#include	<unistd.h>
#include	<netinet/ip.h>
#include	<arpa/inet.h>
#include	<netdb.h>
#include	<fcntl.h>
#include	<poll.h>
#include	<sys/ioctl.h>

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


#ifdef WIN32
#define	__ba_errno__	WSAGetLastError()
#else
#define	__ba_errno__	errno
#endif // WIN32


/*
* Defines and includes for enable extend trace and logging
*/
#define		__FAC__	"DHEXMPL"
#define		__TFAC__ __FAC__ ": "
#include	"utility_routines.h"

#include	"avproto.h"		/* TLV encapsulation API	*/
#include	"gost89.h"		/* GOST 89 encryption stuff	*/

#define $SHOW_PTR(var)			$SHOW_PARM(var, var, "%p")
#define $SHOW_STR(var)			$SHOW_PARM(var, (var ? var : "UNDEF(NULL)"), "'%s'")
#define $SHOW_INT(var)			$SHOW_PARM(var, ((int) var), "%d")
#define $SHOW_UINT(var)			$SHOW_PARM(var, ((unsigned) var), "%u")
#define $SHOW_ULL(var)			$SHOW_PARM(var, ((unsigned long long) var), "%llu")
#define $SHOW_UNSIGNED(var)		$SHOW_PARM(var, var, "0x%08x")
#define $SHOW_BOOL(var)			$SHOW_PARM(var, (var ? "ENABLED(TRUE)" : "DISABLED(FALSE)"), "%s");


/* Global configuration parameters */
static	const	int slen = sizeof(struct sockaddr), one = 1, off = 0;
static	int	g_exit_flag = 0, 	/* Global flag 'all must to be stop'	*/
		g_trace = 1,		/* Grobal trace flag */
		g_tmonet = 3,
		g_port = 1394;

static	ASC	g_host = {$ASCINI("127.0.0.1")};

static struct timespec	t_idle = {7, 0};


typedef struct	__rnd_seed__
{
	struct timespec	ts;
	pid_t		pid;
	struct timespec	ts2;
} RND_SEED;


#define	DH$SZ_PRIME	(256)		/* 256 bits for GOST89	*/
#define	DH$SZ_TESTDATA	9

const char VCLOUD$K_PROTOSIG [] = "Z0magic", VCLOUD$K_PADDING [] = "TH3 $tar1et $qu4d";

enum	{
	VCLOUD$K_TAG_DH_P	= 135,
	VCLOUD$K_TAG_DH_G,
	VCLOUD$K_TAG_DH_SPUBK,
	VCLOUD$K_TAG_DH_CPUBK,
	VCLOUD$K_TAG_DATA,

	VCLOUD$K_TAG_PADDING
};

enum	{
	KDEPO$C_WELCOME_DH	= 135,
	KDEPO$C_TESTDATA
};


/* Routines declaration section	*/

inline static int timespec2msec (
		struct timespec *src)
{
	return (src->tv_sec  * 1024) + (src->tv_nsec / 1024);
}




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

	/* Compute public key as : A("publick key") = g ^ a mod p */
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


/*
 *   DESCRIPTION: Write n bytes to the network socket, wait if not all data has been get
 *		but no more then 13 seconds;
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	buf:	A buffer with data to be sent
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	NONE
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
static inline	int xmit_n
		(
		int	sd,
		void	*buf,
		int	bufsz
		)
{
int	status, restbytes = bufsz;
struct pollfd pfd = {sd, POLLOUT, 0};
struct timespec	now, etime, delta = {g_tmonet, 0};
char	*bufp = (char *) buf;

	/* Compute an end of I/O operation time	*/
	if ( status = clock_gettime(CLOCK_REALTIME, &now) )
		return	$LOG(STS$K_FATAL, "clock_gettime()->%d, errno=%d", status, errno);

	__util$add_time (&now, &g_tmonet, &etime);

	for ( restbytes = bufsz; restbytes; )
		{
		/* Do we reach the end of I/O time ? */
		clock_gettime(CLOCK_REALTIME, &now);
		if ( (now.tv_sec >= etime.tv_sec) && (now.tv_nsec >= etime.tv_nsec) )
			break;

		if( 0 >  (status = poll(&pfd, 1, 1000)) && (errno != EINTR) )
			return	$LOG(STS$K_ERROR, "[#%d] poll/select()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
		else if ( (status < 0) && (errno == EINTR) )
			{
			$LOG(STS$K_WARN, "[#%d] poll/select()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
			continue;
			}

		if ( pfd.revents & (~POLLOUT) && (errno != EAGAIN) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_FATAL, "[#%d] poll()->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, errno);

		if ( !(pfd.revents & POLLOUT) )	/* No interesting event			*/
			continue;

		/* Send data to socket buffer	*/
		if ( restbytes == (status = send(sd, bufp, restbytes, MSG_NOSIGNAL)) )
			return	STS$K_SUCCESS; /* Bingo! We has been sent a requested amount of data */

		if ( 0 >= status )
			{
			$LOG(STS$K_ERROR, "[#%d] send(%d octets)->%d, .revents=%08x(%08x), errno=%d",
					sd, restbytes, status, pfd.revents, pfd.events, errno);
			break;
			}

		/* Advance buffer pointer and decrease to be sent byte counter */
		restbytes -= status;
		bufp	+= status;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not put requested %d octets, rest %d octets", sd, bufsz, restbytes);
}



/*
 *   DESCRIPTION: Read n bytes from the network socket, wait if not all data has been get
 *		but no more then 13 seconds.
 *
 *   INPUT:
 *	sd:	Network socket descriptor
 *	buf:	A buffer to accept data
 *	bufsz:	A number of bytes to be read
 *
 *  OUTPUT:
 *	buf:	Received data
 *
 *  RETURN:
 *	condition code, see STS$K_* constant
 */
static	inline	int recv_n
		(
		int	sd,
		void	*buf,
		int	bufsz
		)
{
int	status, restbytes = bufsz;
struct pollfd pfd = {sd, POLLIN, 0};
struct timespec	now, etime, delta = {g_tmonet, 0};
char	*bufp = (char *) buf;


	/* Compute an end of I/O operation time	*/
	if ( status = clock_gettime(CLOCK_REALTIME, &now) )
		return	$LOG(STS$K_FATAL, "clock_gettime()->%d, errno=%d", status, errno);

	__util$add_time (&now, &delta, &etime);

	for ( restbytes = bufsz; restbytes; )
		{
		/* Do we reach the end of I/O time ?*/
		clock_gettime(CLOCK_REALTIME, &now);
		if ( (now.tv_sec >= etime.tv_sec) && (now.tv_nsec >= etime.tv_nsec) )
			break;

		if( 0 >  (status = poll(&pfd, 1, timespec2msec (&delta))) && (errno != EINTR) )
			return	$LOG(STS$K_ERROR, "[#%d] poll/select()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
		else if ( (status < 0) && (errno == EINTR) )
			{
			$LOG(STS$K_WARN, "[#%d] poll/select()->%d, errno=%d, requested %d octets, rest %d octets", sd, status, errno, bufsz, restbytes);
			continue;
			}

		if ( pfd.revents & (~POLLIN) )	/* Unexpected events ?!			*/
			return	$LOG(STS$K_FATAL, "[#%d] poll()->%d, .revents=%08x(%08x), errno=%d",
					sd, status, pfd.revents, pfd.events, errno);

		if ( !(pfd.revents & POLLIN) )	/* Non-interesting event ?		*/
			continue;

		/* Retrieve data from socket buffer	*/
		if ( restbytes == (status = recv(sd, bufp, restbytes, 0)) )
			return	STS$K_SUCCESS; /* Bingo! We has been received a requested amount of data */

		if ( (0 >= status) && (errno != EINPROGRESS) )
			{
			$LOG(STS$K_ERROR, "[#%d] recv(%d octets)->%d, .revents=%08x(%08x), errno=%d",
					sd, restbytes, status, pfd.revents, pfd.events, errno);
			break;
			}

		/* Advance buffer pointer and decrease expected byte counter */
		restbytes -= status;
		bufp	+= status;
		}

	return	$LOG(STS$K_ERROR, "[#%d] Did not get requested %d octets in %d msecs, rest %d octets", sd, bufsz, timespec2msec (&delta), restbytes);
}




static int	pdu_xmit(
		int	sd,
		void	*pdubuf
			)

{
unsigned status, u_len, u_csr, u_seq;

	/* Check magic, extract PDU's Length, CSR, Sequence ... */
	if ( !(1 & avproto_hget (pdubuf, VCLOUD$K_PROTOSIG, &u_len, &u_csr, &u_seq)) )
		return	$LOG(STS$K_ERROR, "Maillformed or invalid PDU's header");

	/* Send the PDU */
	if ( !(1 & (status = xmit_n (sd, pdubuf, sizeof(AVPROTO_HDR) + u_len))) )
		return	$LOG(STS$K_ERROR, "Error transmitting PDU's (len=%d, csr=%#x, seq=%d)", u_len, u_csr, u_seq);

	return	STS$K_SUCCESS;
}

static int	pdu_recv	(
		int	sd,
		void	*pdubuf,
	unsigned	 pdusz
			)

{
unsigned status, u_len, u_csr, u_seq;

	if ( pdusz < sizeof(AVPROTO_HDR) )
		return	$LOG(STS$K_ERROR, "No free space to read PDU's header");

	/* Get PDU header */
	if ( !(1 & (status = recv_n (sd, pdubuf, sizeof(AVPROTO_HDR)))) )
	     return	$LOG(STS$K_ERROR, "Error receiving PDU's header");

	/* Check magic, extract PDU's Length, CSR, Sequence ... */
	if ( !(1 & avproto_hget (pdubuf, VCLOUD$K_PROTOSIG, &u_len, &u_csr, &u_seq)) )
		return	$LOG(STS$K_ERROR, "Maillformed or invalid PDU's header");

	if ( pdusz < (sizeof(AVPROTO_HDR) + u_len) )
		return	$LOG(STS$K_ERROR, "No free space to read PDU's body (len=%d, csr=%#x, seq=%d)", u_len, u_csr, u_seq);

	/* Read rest of the PDU */
	if ( u_len && !(1 & (status = recv_n (sd, pdubuf + sizeof(AVPROTO_HDR), u_len))) )
		return	$LOG(STS$K_ERROR, "Error reading PDU's body (len=%d, csr=%#x, seq=%d)", u_len, u_csr, u_seq);

	return	STS$K_SUCCESS;
}



static	int	th_client	(void)
{
int	status = 0, rc, sd  =-1, len = 0, v_type, i, j;
struct sockaddr_in servaddr = { 0 };
char	pdubuf[8192], buf[512], *cp;
AVPROTO_PDU *pdu = (AVPROTO_PDU *) pdubuf;
BIGNUM	*cprivk, *cpubk, *spubk, *cskey, *p, *g;
gost_ctx gctx;

	/*
	 * Establishing TCP-connection with remote server
	 */
	inet_pton(AF_INET, $ASCPTR(&g_host), &servaddr.sin_addr);
	servaddr.sin_port = htons(g_port);
	servaddr.sin_family = AF_INET;

	$LOG(STS$K_INFO, "Connecting to %s:%d ...", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));

	if ( 0 > (sd = socket(AF_INET, SOCK_STREAM, 0)) )
		return	$LOG(STS$K_ERROR, "socket()->%d, errno=%d", sd, errno);

	if ( 0 > (status = connect(sd, (struct sockaddr *) &servaddr, sizeof(servaddr))) )
		return	$LOG(STS$K_ERROR, "connect()->%d, errno=%d", status, errno);

	$LOG(STS$K_INFO, "Connection with %s:%d has been established, sd=#%d ...", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), sd);

	/*
	 * Expect from server 'welcome' PDU: with p, g, PubKserver
	 */
	$LOG(STS$K_INFO, "Wait for Welcome PDU from server ...");
	if ( 0 > (status = pdu_recv(sd, pdubuf, sizeof(pdubuf))) )
		return	$LOG(STS$K_ERROR, "Error receiving p, g, PubKserver from server");

	$LOG(STS$K_INFO, "Got Welcome PDU with : p, g, PubKserver from server");

	/*
	 * Extract p, g, PubKserver constants from TLV list,
	 * convert from  big-endian form to internal representative
	 */
	$LOG(STS$K_INFO, "Extract : p, g, PubKserver ...");

	len = sizeof(buf);
	if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_DH_P, &v_type, &buf, &len))) )
		return	$LOG(STS$K_ERROR, "No 'p' in the Server's TLV list");

	p = BN_new();
	BN_bin2bn(buf, len, p);

	len = sizeof(buf);
	if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_DH_G, &v_type, &buf, &len))) )
		return	$LOG(STS$K_ERROR, "No 'g' in the Server's TLV list");

	g = BN_new();
	BN_bin2bn(buf, len, g);

	len = sizeof(buf);
	if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_DH_SPUBK, &v_type, &buf, &len))) )
		return	$LOG(STS$K_ERROR, "No 'PubKserver' in the Server's TLV list");

	spubk = BN_new();
	BN_bin2bn(buf, len, spubk);


	/* So we got all necessary initial data from server - display it ! */
	$LOG(STS$K_INFO, "Client context initialization, input data (has been gotten from server) :");
	$LOG(STS$K_INFO, "p             : %s", BN_bn2hex (p));
	$LOG(STS$K_INFO, "g             : %s", BN_bn2hex (g));
	$LOG(STS$K_INFO, "Server DH public key : %s", BN_bn2hex (spubk));

	/* Generate client's Publick/Private kesy [air */
	cprivk = BN_new();
	cpubk = BN_new();

	__dh_client_init(cprivk, p, g, cpubk);

	$LOG(STS$K_INFO, "Client DH private key: %s", BN_bn2hex (cprivk));
	$LOG(STS$K_INFO, "Client DH public key : %s", BN_bn2hex (cpubk));


	/* Compute Session key at server and client sides */
	$LOG(STS$K_INFO, "Session keys generation ...");

	cskey = BN_new();

	__dh_session_key (spubk, cprivk, p, cskey);

	cp = strcpy(buf, BN_bn2hex (cskey));
	rc = strlen(buf) / 2;
	$LOG(STS$K_INFO, "Client DH session key: %s (%d/%d octets/bits)", buf, rc, rc * 8);



	/*
	 * Send to client: p, g, Server's public key
	 *  .....
	 */
	avproto_hset (pdu, VCLOUD$K_PROTOSIG, KDEPO$C_WELCOME_DH,  KDEPO$C_WELCOME_DH + 1);

	avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_DH_CPUBK, TAG$K_BBLOCK, buf, BN_bn2bin(cpubk, buf) );

	if ( g_trace )
		avproto_dump (pdu);

	/* Send Welcome PDU over has been established TCP-connection ...*/
	if ( !(1 & (status = pdu_xmit (sd, pdu))) )
		return	$LOG(status, "Error sending Welcome PDU");

	/*
	 * At this point we are ready to performs encryption of the payload part of the PDU;
	** PDU (protocol data unit) - consists two parts: header and payload
	** in this demonstration we will encrypt/decrypt only payload part of the PDU:
	**
	**	+--------+----------------------+
	**	|        |			|
	**      | Header | Payload (TLV List)	|
	**	|        |			|
	**	+--------+----------------------+
	**	 Plain   |  Encrypted part
	**
	** So initialize GOST 89 context with default parameters
	**/
	gost_init(&gctx, NULL);


	/* Receive 13 PDU s ... */
	for (i = 0; i < 13; i++)
		{
		if ( 0 > (status = pdu_recv(sd, pdubuf, sizeof(pdubuf))) )
			return	$LOG(STS$K_ERROR, "Error receiving TestData PDU");

		/* Get length of the payload from PDU's header */
		len = be32toh(pdu->r_hdr.u_len);
		cp = (char *) &pdu->r_tlv[0];

		$DUMPHEX(&pdu->r_tlv[0], len);

		/* Decrypt payload part of the PDU, we don't account that GOST 89 is a 8-byte/block alghorytm,
		 * just be ensure that a length of the PDU buffer is enough more the actual length of the PDU's payload
		 */
		for (j = len/8; j--; cp += 8)
			gostdecrypt(&gctx, cp, cp);	/*encrypts one 64 bit block */

		if ( len % 8 )
			gostdecrypt(&gctx, cp, cp);

		/* Extract a TLV with test data from PDU */
		len = sizeof(buf);
		if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_DATA, &v_type, &buf, &len))) )
			return	$LOG(STS$K_ERROR, "No DATA in the Server's TLV list");

		$DUMPHEX(&buf, len);
		}

	while ( !g_exit_flag )
		for ( status = 2; status = sleep(status); );
}



static	int	th_server ( void )
{
int	status, sd = -1, insd = -1, len, v_type, rc, i, j;
char	buf [512] = {0}, *cp, pdubuf[8192];
AVPROTO_PDU *pdu = (AVPROTO_PDU *) pdubuf;
struct sockaddr_in servaddr = {0}, insk = {0};
socklen_t slen = sizeof(struct sockaddr);
BIGNUM	*cpubk, *sprivk, *spubk, *sskey, *p, *g;
gost_ctx gctx;

	$LOG(STS$K_INFO, "Server DH context initialization ...");

	p = BN_new();
	g = BN_new();
	sprivk = BN_new();
	spubk = BN_new();

	__dh_server_init(sprivk, p, g, spubk);

	$LOG(STS$K_INFO, "       p             : %s", BN_bn2hex (p));
	$LOG(STS$K_INFO, "       g             : %s", BN_bn2hex (g));

	$LOG(STS$K_INFO, "Server DH private key: %s", BN_bn2hex (sprivk));
	$LOG(STS$K_INFO, "Server DH public key : %s", BN_bn2hex (spubk));

	/* Initialize a TCP listener on local address/port ... */
	inet_pton(AF_INET, $ASCPTR(&g_host), &servaddr.sin_addr);
	servaddr.sin_port = htons(g_port);
	servaddr.sin_family = AF_INET;

	$LOG(STS$K_INFO, "Initialize listener on : %s:%d ...", inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port));

	if ( 0 > (sd = socket(AF_INET, SOCK_STREAM, 0)) )
		return	$LOG(STS$K_FATAL, "socket(), errno=%d", errno);

	/* avoid EADDRINUSE error on bind() */
	#ifdef	SO_REUSEADDR
	if( 0 > setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one))  )
		$LOG(STS$K_WARN, "setsockopt(%d, SO_REUSEADDR), errno=%d", sd, errno);
	#endif	/* SO_REUSEADDR */


	#ifdef	SO_REUSEPORT
	if( 0 > setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (char *)&one, sizeof(one))  )
		$LOG(STS$K_WARN, "setsockopt(%d, SO_REUSEPORT), errno=%d", sd, errno);
	#endif	/* SO_REUSEADDR */


	if ( 0 > bind(sd, (struct sockaddr*) &servaddr, slen) )
		return	$LOG(STS$K_FATAL, "bind(%d, %s:%d), errno=%d", sd, inet_ntoa(servaddr.sin_addr), ntohs(servaddr.sin_port), errno);

	/*
	 * So, at this point we are ready to accept TCP-connection request from remote client ...
	 * so, wait ...
	 */
	if ( listen(sd, 1) < 0)
		return	$LOG(STS$K_FATAL, "listen(%d, %d), errno=%d", sd, 1, errno);

	slen = sizeof(insk);

	if ( 0 > (insd = accept(sd, (struct sockaddr*)&insk, &slen)) )
		return	$LOG(STS$K_FATAL, "accept(%d), errno=%d", sd, errno);

	$LOG(STS$K_SUCCESS, "[#%d] Accept connection request from %s:%d on #%d", sd, inet_ntoa(insk.sin_addr), ntohs(insk.sin_port), insd);

	/*
	 * Send to client: p, g, Server's public key
	 *  .....
	 */
	avproto_hset (pdu, VCLOUD$K_PROTOSIG, KDEPO$C_WELCOME_DH,  KDEPO$C_WELCOME_DH + 1);

	avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_DH_P, TAG$K_BBLOCK, buf, BN_bn2bin(p, buf) );
	avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_DH_G, TAG$K_BBLOCK, buf, BN_bn2bin(g, buf) );
	avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_DH_SPUBK, TAG$K_BBLOCK, buf, BN_bn2bin(spubk, buf) );

	if ( g_trace )
		avproto_dump (pdu);

	/* Send Welcome PDU over has been established TCP-connection ...*/
	if ( !(1 & (status = pdu_xmit (insd, pdu))) )
		return	$LOG(status, "Error sending Welcome PDU");

	/*
	 * Wait for PubKclient ...
	 */
	$LOG(STS$K_INFO, "Wait for Welcome/Answer PDU from client ...");

	if ( 0 > (status = pdu_recv(insd, pdubuf, sizeof(pdubuf))) )
		return	$LOG(STS$K_ERROR, "Error receiving PubKclient");

	$LOG(STS$K_INFO, "Got Welcome/Answer PDU with : PubKclient");

	/*
	 * Extract Client's Publick Key from TLV list ...
	 */
	$LOG(STS$K_INFO, "Extract : PubKclient ...");

	len = sizeof(buf);
	if ( !(1 & (status = avproto_get (pdu, NULL, VCLOUD$K_TAG_DH_CPUBK, &v_type, &buf, &len))) )
		return	$LOG(STS$K_ERROR, "No 'PubKclient' in the Server's TLV list");

	/* Convert Client's Publick Key from big-endian form to internal representative */
	cpubk = BN_new();
	BN_bin2bn(buf, len, cpubk);

	/* Compute Session key  */
	$LOG(STS$K_INFO, "Session keys generation ...");

	sskey = BN_new();

	__dh_session_key (cpubk, sprivk, p, sskey);
	cp = strcpy(buf, BN_bn2hex (sskey));
	rc = strlen(buf) / 2;
	$LOG(STS$K_INFO, "Server DH session key: %s (%d/%d octets/bits)", buf, rc, rc * 8);

	/*
	 * At this point we are ready to performs encryption of the payload part of the PDU;
	** PDU (protocol data unit) - consists two parts: header and payload
	** in this demonstration we will encrypt/decrypt only payload part of the PDU:
	**
	**	+--------+----------------------+
	**	|        |			|
	**      | Header | Payload (TLV List)	|
	**	|        |			|
	**	+--------+----------------------+
	**	 Plain   |  Encrypted part
	**
	** So initialize GOST 89 context with default parameters
	**/
	gost_init(&gctx, NULL);


	/* Send 13 PDU s ... */
	for (i = 0; i < 13; i++)
		{
		/* Fill buffer with test data , make PDU */
		avproto_hset (pdu, VCLOUD$K_PROTOSIG, KDEPO$C_TESTDATA,  KDEPO$C_TESTDATA);

		memset(buf, 0, sizeof(buf));
		memset(buf, 'A' + i, DH$SZ_TESTDATA);
		avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_DATA, TAG$K_BBLOCK, buf, DH$SZ_TESTDATA );


		/* Be advised that the GOST 89 is the 64-bits block algoritm, so we need to pad encrypted block
		 * at 8 octets/64 bits boundary.
		 *
		 * In our case we will just add special TLV with 7 octets length of data, this
		 * TLV must be last added !!!
		 */
		avproto_put (pdu, sizeof(pdubuf), VCLOUD$K_TAG_PADDING, TAG$K_BBLOCK, VCLOUD$K_PADDING,  sizeof (VCLOUD$K_PADDING));

		/* Get length of the payload from PDU's header */
		len = be32toh(pdu->r_hdr.u_len);
		cp = (char *) &pdu->r_tlv[0];



		/* Encrypt payload, we don't account that GOST 89 is a 8-byte/block alghorytm,
		 * just be ensure that a length of the PDU buffer is enough more the actual length of the PDU's payload
		 */
		for (j = len/8; j--; cp += 8)
			gostcrypt(&gctx, cp, cp);	/*encrypts one 64 bit block */

		if ( status = len % 8 )
			gostcrypt(&gctx, cp, cp);



		/* Send TestData PDU over has been established TCP-connection ...*/
		if ( !(1 & (status = pdu_xmit (insd, pdu))) )
			return	$LOG(status, "Error sending TestData PDU");

		$DUMPHEX(&pdu->r_tlv[0], len);
		}



	for ( status = 13; status = sleep(status); );

	close (insd);
	close(sd);

	pthread_exit(&status);
}

int	main	(int argc, char **argv)
{
int	status, rc;
char	*cp, buf[512];
BIGNUM	*cprivk, *cpubk, *sprivk, *spubk, *sskey, *cskey, *p, *g;
BN_CTX	*bn_ctx; /* used internally by the bignum lib */
pthread_t	tid;

#if	0
	$LOG(STS$K_INFO, "Server context initialization ...");

	p = BN_new();
	g = BN_new();
	sprivk = BN_new();
	spubk = BN_new();

	__dh_server_init(sprivk, p, g, spubk);

	$LOG(STS$K_INFO, "       p             : %s", BN_bn2hex (p));
	$LOG(STS$K_INFO, "       g             : %s", BN_bn2hex (g));

	$LOG(STS$K_INFO, "Server DH private key: %s", BN_bn2hex (sprivk));
	$LOG(STS$K_INFO, "Server DH public key : %s", BN_bn2hex (spubk));


	/*
	 * Send to client: p, g, Server's publick key
	 *  .....
	 */


	/* Generate client's keys  with has been given from server: A  (erver's public key), p, g */
	$LOG(STS$K_INFO, "Client context initialization, input data (has been gotten from server) :");
	$LOG(STS$K_INFO, "\t       p             : %s", BN_bn2hex (p));
	$LOG(STS$K_INFO, "\t       g             : %s", BN_bn2hex (g));
	$LOG(STS$K_INFO, "\tServer DH public key : %s", BN_bn2hex (spubk));

	cprivk = BN_new();
	cpubk = BN_new();

	__dh_client_init(cprivk, p, g, cpubk);

	$LOG(STS$K_INFO, "Client DH private key: %s", BN_bn2hex (cprivk));
	$LOG(STS$K_INFO, "Client DH public key : %s", BN_bn2hex (cpubk));


	/* Compute Session key at server and client sides */
	$LOG(STS$K_INFO, "Session keys generation ...");

	sskey = BN_new();
	cskey = BN_new();

	__dh_session_key (cpubk, sprivk, p, sskey);
	cp = strcpy(buf, BN_bn2hex (sskey));
	rc = strlen(buf) / 2;
	$LOG(STS$K_INFO, "Server DH session key: %s (%d/%d octets/bits)", buf, rc, rc * 8);

	__dh_session_key (spubk, cprivk, p, cskey);
	cp = strcpy(buf, BN_bn2hex (cskey));
	rc = strlen(buf) / 2;
	$LOG(STS$K_INFO, "Client DH session key: %s (%d/%d octets/bits)", buf, rc, rc * 8);



#endif
	/*
	 * Second part of the demonstration ...
	 */
	status = pthread_create(&tid, NULL, th_server, NULL);
	$LOG(STS$K_INFO, "Server thread has been created, status = %d", status);

	/* Take 2 second to server thread to be ready to acccept client's connection ... */
	for ( status = 2; status = sleep(status); );

	status = pthread_create(&tid, NULL, th_client, NULL);
	$LOG(STS$K_INFO, "Client thread has been created, status = %d", status);


	/* Hibernate ... */
	while ( !g_exit_flag )
		{
		for ( status = 2; status = sleep(status); );
		$LOG(STS$K_INFO, "Press Control-C to stop ...", status);
		}
}
