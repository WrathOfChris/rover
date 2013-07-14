/* $Gateweaver: robin_util.c,v 1.37 2007/05/28 23:21:03 cmaxwell Exp $ */
/*
 * Copyright (c) 2005 Christopher Maxwell.  All rights reserved.
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "robin_locl.h"
#include <kerberosV/krb5.h>

#ifndef lint
RCSID("$Gateweaver: robin_util.c,v 1.37 2007/05/28 23:21:03 cmaxwell Exp $");
#endif

void
robin_set_logging(int loglevel)
{
	robin_verbose = loglevel;
}

int
robin_set_hostname(RobinHost *host, const char *hostname)
{
	char *p;

	if (host == NULL)
		return ROBIN_API_INVALID;

	if ((p = strdup(hostname)) == NULL)
		return ROBIN_API_NOMEM;

	if (host->hostname)
		free(host->hostname);
	host->hostname = p;

	return ROBIN_SUCCESS;
}

/*
 * Copy relevant portions of the hostaddr into a sockaddr
 */
int
robin_hostaddr2sockaddr(const RobinHostAddress *ha, struct sockaddr *sa)
{
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;

	if (ha == NULL || sa == NULL)
		return ROBIN_API_INVALID;

	switch (ha->addr_type) {
		case ROBIN_ADDRESS_INET:
			sin4 = (struct sockaddr_in *)sa;
			if (ha->address.length != sizeof(struct in_addr))
				return ROBIN_BADADDR;
			sin4->sin_family = AF_INET;
			sin4->sin_len = sizeof(struct sockaddr_in);
			sin4->sin_port = ha->port;
			bcopy(ha->address.data, &sin4->sin_addr, ha->address.length);
			break;

		case ROBIN_ADDRESS_INET6:
			sin6 = (struct sockaddr_in6 *)sa;
			if (ha->address.length != sizeof(struct in6_addr))
				return ROBIN_BADADDR;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(struct sockaddr_in6);
			sin6->sin6_port = ha->port;
			bcopy(ha->address.data, &sin6->sin6_addr, ha->address.length);
			break;

		case ROBIN_ADDRESS_NONE:
		case ROBIN_ADDRESS_LOCAL:
		case ROBIN_ADDRESS_ADDRPORT:
		case ROBIN_ADDRESS_IPPORT:
		case ROBIN_ADDRESS_SELF:
			return ROBIN_BADADDR;
	}

	return ROBIN_SUCCESS;
}

/*
 * Copy relevant portions of the sockaddr into a hostaddr
 */
int
robin_sockaddr2hostaddr(const struct sockaddr *sa, RobinHostAddress *ha)
{
	const struct sockaddr_in *sin4;
	const struct sockaddr_in6 *sin6;

	if (sa == NULL || ha == NULL)
		return ROBIN_API_INVALID;

	/* free before, just in case */
	free_RobinHostAddress(ha);

	switch (sa->sa_family) {
		case AF_INET:
			sin4 = (const struct sockaddr_in *)sa;
			ha->addr_type = ROBIN_ADDRESS_INET;
			ha->address.length = sizeof(struct in_addr);
			if ((ha->address.data = calloc(1, ha->address.length)) == NULL)
				return ROBIN_API_NOMEM;
			ha->port = sin4->sin_port;
			bcopy(&sin4->sin_addr, ha->address.data, ha->address.length);
			break;

		case AF_INET6:
			sin6 = (const struct sockaddr_in6 *)sa;
			ha->addr_type = ROBIN_ADDRESS_INET6;
			ha->address.length = sizeof(struct in6_addr);
			if ((ha->address.data = calloc(1, ha->address.length)) == NULL)
				return ROBIN_API_NOMEM;
			ha->port = sin6->sin6_port;
			bcopy(&sin6->sin6_addr, ha->address.data, ha->address.length);
			break;

		default:
			return ROBIN_BADADDR;
	}

	return ROBIN_SUCCESS;
}

/*
 * Add the address contained within the sockaddr (sa) to the address list of
 * (host).  It is not a failure if the address already exists.
 */
int
robin_add_hostaddr(RobinHost *host, const struct sockaddr *sa)
{
	RobinHostAddresses *has;
	RobinHostAddress addr, *h;
	int ret;
	unsigned int i;

	if (host == NULL || sa == NULL)
		return ROBIN_API_INVALID;

	bzero(&addr, sizeof(addr));
	if ((ret = robin_sockaddr2hostaddr(sa, &addr)))
		goto out;

	has = &host->addresses;
	for (i = 0; i < has->len; i++)
		if (has->val[i].addr_type == addr.addr_type
				&& has->val[i].address.length == addr.address.length
				&& memcmp(has->val[i].address.data, addr.address.data,
					addr.address.length) == 0) {
			ret = ROBIN_SUCCESS;
			goto out;
		}

	if ((h = realloc(has->val, (has->len + 1) * sizeof(*h))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto out;
	}

	/* tack the new address onto the end, then increment the length */
	has->val = h;
	bcopy(&addr, &has->val[has->len], sizeof(addr));
	has->len += 1;

	return ROBIN_SUCCESS;

out:
	free_RobinHostAddress(&addr);
	return ret;
}

/*
 * Add a hostname to the context cell hostname list.  It is not a failure if
 * the hostname already exists.
 */
int
robin_add_cellhostname(robin_context context, const char *hostname)
{
	if (context == NULL || hostname == NULL)
		return ROBIN_API_INVALID;

	return robin_add_hostname(&context->cell.hosts, hostname);
}

int
robin_get_cellhost(robin_context context, const char *hostname, RobinHost **host)
{
	if (context == NULL || hostname == NULL || host == NULL)
		return ROBIN_API_INVALID;

	return robin_get_host(&context->cell.hosts, hostname, host);
}

int
robin_get_host(const RobinHosts *hosts, const char *hostname, RobinHost **host)
{
	unsigned int i;

	if (hosts == NULL || hostname == NULL || host == NULL)
		return ROBIN_API_INVALID;

	for (i = 0; i < hosts->len; i++)
		if (strcasecmp(hostname, hosts->val[i].hostname) == 0) {
			*host = &hosts->val[i];
			return ROBIN_SUCCESS;
		}

	return ROBIN_NOTFOUND;
}

/*
 * Add a new RobinHost to a list of RobinHosts
 */
int
robin_add_hostname(RobinHosts *hosts, const char *hostname)
{
	RobinHost *h, host;
	unsigned int i;

	if (hosts == NULL || hostname == NULL)
		return ROBIN_API_INVALID;

	for (i = 0; i < hosts->len; i++)
		if (strcasecmp(hostname, hosts->val[i].hostname) == 0)
			return ROBIN_SUCCESS;

	bzero(&host, sizeof(host));
	if ((host.hostname = strdup(hostname)) == NULL)
		return ROBIN_API_NOMEM;

	if ((h = realloc(hosts->val, (hosts->len + 1) * sizeof(host))) == NULL) {
		free(host.hostname);
		return ROBIN_API_NOMEM;
	}

	hosts->val = h;
	bcopy(&host, &hosts->val[hosts->len], sizeof(host));
	hosts->len += 1;

	return ROBIN_SUCCESS;
}

const char *
robin_print_hostaddr(const RobinHostAddress *ha)
{
	struct sockaddr_storage ss = {0};

	if (robin_hostaddr2sockaddr(ha, (struct sockaddr *)&ss))
		return "(error)";

	return log_sockaddr((struct sockaddr *)&ss);
}

int
robin_append_hostaddr(RobinHost *host, const RobinHostAddress *addr)
{
	struct sockaddr_storage ss = {0};
	int ret;

	if ((ret = robin_hostaddr2sockaddr(addr, (struct sockaddr *)&ss)))
		return ret;

	return robin_add_hostaddr(host, (struct sockaddr *)&ss);
}

static struct {
	ROBIN_TYPE rtc;
	char *rtl;
	char *rtr;
} robin_typelist[] = {
	{ RTYPE_GENERIC,	"0",	"GENERIC" },
	{ RTYPE_REGULAR,	"-",	"REGULAR" },
	{ RTYPE_DIRECTORY,	"D",	"DIRECTORY" },
	{ RTYPE_SYMLINK,	"L",	"SYMLINK" },
	{ RTYPE_VOLUME,		"V",	"VOLUME" },
	{ RTYPE_GRAFT,		"G",	"GRAFT" },
	{ RTYPE_AUTHORITY,	"A",	"AUTHORITY" },
	{ UINT_MAX,			NULL,	NULL }
};

const char *
robin_type(ROBIN_TYPE type)
{
	int i;
	for (i = 0; robin_typelist[i].rtc != UINT_MAX; i++)
		if (robin_typelist[i].rtc == type)
			return robin_typelist[i].rtr;
	return "(unknown)";
}

const char *
robin_type_short(ROBIN_TYPE type)
{
	int i;
	for (i = 0; robin_typelist[i].rtc != UINT_MAX; i++)
		if (robin_typelist[i].rtc == type)
			return robin_typelist[i].rtl;
	return "(unknown)";
}

const char *
robin_rights(ROBIN_RIGHT right)
{
	return tbox_units(ROBIN_RIGHT2int(right), asn1_ROBIN_RIGHT_units());
}

const char *
robin_rights_short(ROBIN_RIGHT right)
{
	return tbox_units_short(ROBIN_RIGHT2int(right), asn1_ROBIN_RIGHT_units());
}

const char *
robin_locktype(ROBIN_LOCKTYPE lock)
{
	static char lmode[5];

	lmode[0] = lmode[1] = lmode[2] = lmode[3] = '-'; lmode[4] = '\0';
	
	if (lock.lock_break && lock.lock_nl)
		lmode[0] = '~';
	else if (lock.lock_break)
		lmode[0] = '!';
	else if (lock.lock_nl)
		lmode[0] = 'n';

	if ((lock.lock_cr) && (lock.lock_cw))
		lmode[1] = 'W';
	else if (lock.lock_cr)
		lmode[1] = 'r';
	else if (lock.lock_cw)
		lmode[1] = 'w';

	if ((lock.lock_pr) && (lock.lock_pw))
		lmode[2] = 'W';
	else if (lock.lock_pr)
		lmode[2] = 'r';
	else if (lock.lock_pw)
		lmode[2] = 'w';

	if (lock.lock_ex)
		lmode[3] = 'X';

	return lmode;
}

int
robin_handlecmp(const RobinHandle *a, const RobinHandle *b)
{
	if (a->vol < b->vol)
		return -1;
	if (a->vol > b->vol)
		return 1;

	if (a->ino < b->ino)
		return -1;
	if (a->ino > b->ino)
		return 1;

	if (a->gen < b->gen)
		return -1;
	if (a->gen > b->gen)
		return 1;

	if (a->ver < b->ver)
		return -1;
	if (a->ver > b->ver)
		return 1;

	return 0;
}

int
robin_checksumcmp(const RobinChecksum *a, const RobinChecksum *b)
{
	if (a->cksumtype < b->cksumtype)
		return -1;
	if (a->cksumtype > b->cksumtype)
		return 1;

	if (a->checksum.length < b->checksum.length)
		return -1;
	if (a->checksum.length > b->checksum.length)
		return 1;

	return memcmp(a->checksum.data, b->checksum.data, a->checksum.length);
}

int
robin_checksumcpy(const RobinChecksum *from, RobinChecksum *to)
{
	if (to->checksum.length && to->checksum.data)
		free_RobinChecksum(to);
	return copy_RobinChecksum(from, to);
}

const char *
robin_print_clientname(robin_con con)
{
	return pigeon_print_clientname(con->p);
}

const char *
robin_print_servername(robin_con con)
{
	return pigeon_print_servername(con->p);
}

int
robin_filltime(RobinTime *rt, int64_t secs, int32_t nanosecs)
{
	if (rt == NULL)
		return -1;
	rt->secs = secs;
	/* nanosecs are 1e-09 */
	if (nanosecs >= 0 && nanosecs <= 1000000000)
		rt->nsec = nanosecs;
	else
		rt->nsec = 0;

	return 0;
}

int
robin_cmptime(const RobinTime *a, const RobinTime *b)
{
	if (a->secs < b->secs)
		return -1;
	if (a->secs > b->secs)
		return 1;

	if (a->nsec < b->nsec)
		return -1;
	if (a->nsec > b->nsec)
		return 1;

	return 0;
}

/*
 * Extract a principal from the underlying pigeon connection
 */
int
robin_principal(robin_con con, RobinPrincipal *principal)
{
	char *name = NULL, *p;

	if (con->p == NULL || con->p->ctx == NULL)
		return ROBIN_DISCONNECTED;

	if (con->mode == PIGEON_MODE_USER || con->mode == PIGEON_MODE_CLIENT)
		name = pigeon_print_clientname(con->p);
	else if (con->mode == PIGEON_MODE_SERVER)
		name = pigeon_print_servername(con->p);
	else
		return ROBIN_API_INVALID;

	if ((p = strrchr(name, '@')) == NULL)
		principal->cell = strdup("");
	else {
		*p = '\0';
		principal->cell = strdup(p+1);
	}
	if (principal->cell == NULL)
		return ROBIN_API_NOMEM;

	/* dup name */
	if ((principal->name = strdup(name)) == NULL)
		return ROBIN_API_NOMEM;

	return ROBIN_SUCCESS;
}

/*
 * The OTHER principal.  As in, the one i MEANT, not the one i asked for.
 */
int
robin_principal_other(robin_con con, RobinPrincipal *principal)
{
	char *name = NULL, *p;

	if (con->p == NULL || con->p->ctx == NULL)
		return ROBIN_DISCONNECTED;

	if (con->mode == PIGEON_MODE_USER || con->mode == PIGEON_MODE_CLIENT)
		name = pigeon_print_servername(con->p);
	else if (con->mode == PIGEON_MODE_SERVER)
		name = pigeon_print_clientname(con->p);
	else
		return ROBIN_API_INVALID;

	if ((p = strrchr(name, '@')) == NULL)
		principal->cell = strdup("");
	else {
		*p = '\0';
		principal->cell = strdup(p+1);
	}
	if (principal->cell == NULL)
		return ROBIN_API_NOMEM;

	/* dup name */
	if ((principal->name = strdup(name)) == NULL)
		return ROBIN_API_NOMEM;

	return ROBIN_SUCCESS;
}

void
robin_right_setall(ROBIN_RIGHT *rr)
{
	int i, r = 0;
	for (i = 0; asn1_ROBIN_RIGHT_units()[i].name; i++)
		r |= asn1_ROBIN_RIGHT_units()[i].mult;
	*rr = int2ROBIN_RIGHT(r);

	/* unset propagation flags */
	rr->pfile = 0;
	rr->pdir = 0;
	rr->ponly = 0;
	rr->pstop = 0;

	/* unset local flags */
	rr->local1 = 0;
	rr->local2 = 0;
	rr->local3 = 0;
	rr->local4 = 0;
	rr->local5 = 0;
	rr->local6 = 0;
	rr->local7 = 0;
	rr->local8 = 0;
}

int
robin_principal_compare(const RobinPrincipal *a, const RobinPrincipal *b)
{
	int ret;

	if ((a->cell && b->cell == NULL) || (a->cell == NULL && b->cell))
		return a->cell ? 1 : -1;
	else if (a->cell && b->cell)
		if ((ret = strcasecmp(a->cell, b->cell)))
			return ret;

	if ((a->name && b->name == NULL) || (a->name == NULL && b->name))
		return a->name ? 1 : -1;
	else if (a->name && b->name)
		if ((ret = strcasecmp(a->name, b->name)))
			return ret;

	return 0;
}

const char *
robin_log_princ(const RobinPrincipal *princ)
{
	static char namebuf[NAME_MAX + 1];

	if (princ == NULL)
		return "(error)";
	if (princ->name == NULL)
		return "(name error)";
	if (princ->cell == NULL)
		return "(cell error)";

	if (strlcpy(namebuf, princ->name, sizeof(namebuf)) >= sizeof(namebuf)
			|| strlcat(namebuf, "@", sizeof(namebuf)) >= sizeof(namebuf)
			|| strlcat(namebuf, princ->cell, sizeof(namebuf))
				>= sizeof(namebuf))
		return "(error)";

	return namebuf;
}

const char *
robin_log_checksum(const RobinChecksum *sum)
{
	static char sumbuf[sizeof("SHA512") + 1 + (RCKSUM_LENGTH * 2)];
	char *p = NULL;
	char hexc[4];
	uint8_t *h;

	if (sum == NULL)
		return "error";

	switch (sum->cksumtype) {
		case RCKSUMTYPE_NONE:	p = "NONE"; break;
		case RCKSUMTYPE_MD5:	p = "MD5"; break;
		case RCKSUMTYPE_SHA1:	p = "SHA1"; break;
		case RCKSUMTYPE_RMD160:	p = "RMD160"; break;
		case RCKSUMTYPE_SHA256:	p = "SHA256"; break;
		case RCKSUMTYPE_SHA384:	p = "SHA384"; break;
		case RCKSUMTYPE_SHA512:	p = "SHA512"; break;
		case RCKSUMTYPE_ROLL32:	p = "ROLL32"; break;
		case RCKSUMTYPE_MD4:	p = "MD4"; break;
		default:				p = "INVALID"; break;
	}

	/* yeah its ugly, but its controlled */
	strlcpy(sumbuf, p, sizeof(sumbuf));

	if (sum->checksum.length > 0)
		strlcat(sumbuf, ":", sizeof(sumbuf));

	for (h = (uint8_t *)sum->checksum.data;
			h < (uint8_t *)sum->checksum.data + sum->checksum.length; h++) {
		snprintf(hexc, sizeof(hexc), "%.2X", *h);
		if (strlcat(sumbuf, hexc, sizeof(sumbuf)) >= sizeof(sumbuf))
			return "overflow";
	}

	return sumbuf;
}

int
robin_name2princ(robin_context context, const char *name, RobinPrincipal *princ)
{
	char *p;

	if (context == NULL || name == NULL || princ == NULL)
		return ROBIN_API_INVALID;

	if ((p = strrchr(name, '@')) == NULL) {
		princ->cell = strdup(context->cell.cellname);
		p = (char *)name + strlen(name);
	} else
		princ->cell = strdup(p+1);
	if (princ->cell == NULL)
		return ROBIN_API_NOMEM;

	if ((princ->name = calloc(1, (p - name) + 1)) == NULL) {
		free(princ->cell);
		princ->cell = NULL;
		return ROBIN_API_NOMEM;
	}

	bcopy(name, princ->name, (p - name));
	*(princ->name + (p - name)) = '\0';

	return ROBIN_SUCCESS;
}

/*
 * Conversion functions.
 */
krb5_cksumtype
robin_cksum2krb(ROBIN_CKSUMTYPE ctype)
{
	switch (ctype) {
		case RCKSUMTYPE_NONE:
			return CKSUMTYPE_NONE;
		case RCKSUMTYPE_MD5:
			return CKSUMTYPE_RSA_MD5;
		case RCKSUMTYPE_SHA1:
			return CKSUMTYPE_SHA1;
		case RCKSUMTYPE_RMD160:
			return CKSUMTYPE_NONE;		/* XXX */
		case RCKSUMTYPE_SHA256:
			return CKSUMTYPE_HMAC_SHA1_96_AES_256;
		case RCKSUMTYPE_SHA384:
			return CKSUMTYPE_NONE;		/* XXX */
		case RCKSUMTYPE_SHA512:
			return CKSUMTYPE_NONE;		/* XXX */
		case RCKSUMTYPE_ROLL32:
			return CKSUMTYPE_NONE;		/* XXX */
		case RCKSUMTYPE_MD4:
			return CKSUMTYPE_RSA_MD4;
	}

	return 0;
}

ROBIN_CKSUMTYPE
robin_krb2cksum(krb5_cksumtype ctype)
{
	switch (ctype) {
		case CKSUMTYPE_NONE:
			return RCKSUMTYPE_NONE;
		case CKSUMTYPE_RSA_MD4:
			return RCKSUMTYPE_MD4;
		case CKSUMTYPE_RSA_MD5:
			return RCKSUMTYPE_MD5;
		case CKSUMTYPE_SHA1:
			return RCKSUMTYPE_SHA1;
		case CKSUMTYPE_HMAC_SHA1_96_AES_256:
			return RCKSUMTYPE_SHA256;
		default:
			log_debug("unhandled krb5 checksum type %d", ctype);
			break;
	}
	return RCKSUMTYPE_NONE;
}

krb5_cksumtype
robin_token2krb(TOKENTYPE ttype)
{
	switch (ttype) {
		case TOKENTYPE_NONE:
			return CKSUMTYPE_NONE;

		case TOKENTYPE_CONFIG:
			return CKSUMTYPE_NONE;		/* XXX */

		case TOKENTYPE_FAKE:
			return CKSUMTYPE_NONE;		/* XXX */

		case TOKENTYPE_AES128_CTS_HMAC_SHA1_96:
			return CKSUMTYPE_HMAC_SHA1_96_AES_128;

		case TOKENTYPE_AES256_CTS_HMAC_SHA1_96:
			return CKSUMTYPE_HMAC_SHA1_96_AES_256;
	}
	log_debug("unhandled token type %d", ttype);
	return 0;
}

TOKENTYPE
robin_krb2token(krb5_cksumtype etype)
{
	switch (etype) {
		case CKSUMTYPE_NONE:
			return TOKENTYPE_NONE;

		case CKSUMTYPE_HMAC_SHA1_96_AES_128:	/* */
			return TOKENTYPE_AES128_CTS_HMAC_SHA1_96;

		case CKSUMTYPE_HMAC_SHA1_96_AES_256:	/* aes256-cts-hmac-sha1-96 */
			return TOKENTYPE_AES256_CTS_HMAC_SHA1_96;

		case CKSUMTYPE_CRC32:					/* des-cbc-crc */
		case CKSUMTYPE_RSA_MD5_DES:				/* des-cbc-md5 */
		case CKSUMTYPE_RSA_MD4_DES:				/* des-cbc-md4 */
		case CKSUMTYPE_HMAC_SHA1_DES3:			/* des3-cbc-sha1 */
		case CKSUMTYPE_HMAC_MD5:				/* arcfour-hmac-md5 */
		default:
			log_debug("unhandled krb5 encryption type %d", etype);
	}
	return TOKENTYPE_NONE;
}

/*
 * Like strdup(3), but for principals
 */
RobinPrincipal *
robin_princdup(const RobinPrincipal *princ)
{
	RobinPrincipal *p;

	if ((p = calloc(1, sizeof(*p))) == NULL)
		return NULL;
	if (copy_RobinPrincipal(princ, p)) {
		free(p);
		return NULL;
	}

	return p;
}

RobinHandle *
robin_handledup(const RobinHandle *hdl)
{
	RobinHandle *h;

	if ((h = calloc(1, sizeof(*h))) == NULL)
		return NULL;
	if (copy_RobinHandle(hdl, h)) {
		free(h);
		return NULL;
	}

	return h;
}

int
robin_get_conhost(robin_context context, robin_con con, RobinHost **host)
{
	if (context == NULL || con == NULL || host == NULL)
		return ROBIN_API_INVALID;

	*host = con->host;

	return ROBIN_SUCCESS;
}
