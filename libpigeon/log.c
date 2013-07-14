/* $Gateweaver: log.c,v 1.3 2005/06/16 04:53:57 cmaxwell Exp $ */
/* $OpenBSD: log.c,v 1.4 2004/07/08 01:19:27 henning Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "pigeon_locl.h"

#ifndef lint
RCSID("$Gateweaver: log.c,v 1.3 2005/06/16 04:53:57 cmaxwell Exp $");
#endif

static int __log_debug;

void
log_init(int n_debug)
{
	extern char	*__progname;

	__log_debug = n_debug;

	if (!__log_debug)
		openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	tzset();
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	char	*nfmt;

	if (__log_debug) {
		/* best effort in out of mem situations */
		if (asprintf(&nfmt, "%s\n", fmt) == -1) {
			vfprintf(stderr, fmt, ap);
			fprintf(stderr, "\n");
		} else {
			vfprintf(stderr, nfmt, ap);
			free(nfmt);
		}
		fflush(stderr);
	} else
		vsyslog(pri, fmt, ap);
}

static void
logit(int pri, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

void
log_warn(const char *emsg, ...)
{
	char	*nfmt;
	va_list	 ap;

	/* best effort to even work in out of memory situations */
	if (emsg == NULL)
		logit(LOG_CRIT, "%s", strerror(errno));
	else {
		va_start(ap, emsg);

		if (asprintf(&nfmt, "%s: %s", emsg, strerror(errno)) == -1) {
			/* we tried it... */
			vlog(LOG_CRIT, emsg, ap);
			logit(LOG_CRIT, "%s", strerror(errno));
		} else {
			vlog(LOG_CRIT, nfmt, ap);
			free(nfmt);
		}
		va_end(ap);
	}
}

void
log_warnx(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_CRIT, emsg, ap);
	va_end(ap);
}

void
log_info(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_INFO, emsg, ap);
	va_end(ap);
}

void
log_debug(const char *emsg, ...)
{
	va_list	 ap;

	if (__log_debug == 1) {
		va_start(ap, emsg);
		vlog(LOG_DEBUG, emsg, ap);
		va_end(ap);
	}
}

void
fatal(const char *emsg)
{
	if (emsg == NULL)
		logit(LOG_CRIT, "fatal: %s", strerror(errno));
	else
		if (errno)
			logit(LOG_CRIT, "fatal: %s: %s",
			    emsg, strerror(errno));
		else
			logit(LOG_CRIT, "fatal: %s", emsg);

	exit(EX_OSERR);
}

void
fatalx(const char *emsg)
{
	errno = 0;
	fatal(emsg);
}

void
notfatal(const char *emsg)
{
	log_debug(emsg);
}

const char *
log_sockaddr(struct sockaddr *sa)
{
	static char	buf[NI_MAXHOST];

	if (sa->sa_family == AF_UNIX) {
		if (strlen(((struct sockaddr_un *)sa)->sun_path))
			return ((struct sockaddr_un *)sa)->sun_path;
		else
			return "(local user)";
	}

	if (getnameinfo(sa, sa->sa_len, buf, sizeof(buf), NULL, 0,
	    NI_NUMERICHOST))
		return "(unknown)";
	else
		return buf;
}

void
log_hexdump(const unsigned char *data, size_t len)
{
	size_t c, d;
	char ascii[16];
	char hex[49];
	char hexc[4];

	memset(ascii, 0, sizeof(ascii));
	memset(hex, 0, sizeof(hex));

	for (c = 0, d = 0; c < len; c++, d++) {
		if (d >= 16) {
			logit(LOG_INFO, "%-48s\t%.16s", hex, ascii);
			d = 0;
			memset(hex, 0, sizeof(hex));
			memset(ascii, 0, sizeof(ascii));
		}
		snprintf(hexc, sizeof(hexc), " %.2X", (unsigned char)*(data + c));
		strlcat(hex, hexc, sizeof(hex));
		if (isprint(*(data + c)))
			ascii[d] = *(data + c);
		else
			ascii[d] = '.';
	}
	logit(LOG_INFO, "%-48s\t%.16s\n", hex, ascii);
}

void
log_trace(const unsigned char *data, size_t len)
{
	char *safe;
	size_t i;

	if ((safe = calloc(1, len + 1)) == NULL) {
		log_warn("--> trace memory allocation failure");
		return;
	}

	for (i = 0; i < len; i++) {
		if (isprint(*(data + i)))
			*(safe + i) = *(data + i);
		else
			*(safe + i) = '.';
	}

	logit(LOG_DEBUG, "--> %s", safe);

	free(safe);
}
