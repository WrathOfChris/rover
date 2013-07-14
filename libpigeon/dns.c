/* $Gateweaver: dns.c,v 1.11 2006/10/12 18:13:42 cmaxwell Exp $ */
/*
 * Copyright (c) 2004 Christopher Maxwell.  All rights reserved.
 * 
 * Originally from:
 * 	libexec/smtpd/dns.c,v 1.6 2004/12/22 03:27:02 cmaxwell Exp $
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>
#include "pigeon_locl.h"

#ifndef lint
RCSID("$Gateweaver: dns.c,v 1.11 2006/10/12 18:13:42 cmaxwell Exp $");
#endif

static int dns_options = 0;
static int dns_retry = 0;
static int dns_retrans = 0;
static time_t dns_chktime = 30;

static struct dns_nameserver_list dns_servers;
static struct timespec dns_stat_resolv;
static time_t dns_rechktime;

static unsigned char dns_qbuf[DNS_MAXPACKET];
static char dns_hbuf[MAXHOSTNAMELEN];

/* internal functions */
static int dns_mkquery(int, const char *, int, int, const unsigned char *,
		int, unsigned char *, int);
static int dns_opt(int, unsigned char *, int, int);
static int dns_query(const char *, int, int, struct dns_query *);
static int dns_send(struct dns_query *, int);
static int dns_parse(struct dns_query *, unsigned char *, size_t);

int
dns_add_nameserver(struct sockaddr *sa)
{
	struct dns_nameserver *ns;

	if ((ns = calloc(1, sizeof(struct dns_nameserver))) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	memcpy(&ns->ss, sa, sa->sa_len);
	ns->tcp.fd = -1;
	ns->udp.fd = -1;
	TAILQ_INIT(&ns->qq);

	TAILQ_INSERT_TAIL(&dns_servers, ns, entry);

	return 0;
}

static int
dns_check_resolvconf(int usercall)
{
	struct stat sb;
	FILE *fp;
	char *line, *s;
	size_t len, lno;

	if (usercall == 0) {
		if (dns_rechktime >= time(NULL))
			return 0;
		dns_rechktime = time(NULL) + dns_chktime;
		if (stat(_PATH_RESCONF, &sb) != -1) {
			if (timespeccmp(&sb.st_mtimespec, &dns_stat_resolv, ==))
				return 0;
			else
				dns_stat_resolv = sb.st_mtimespec;
		} else {
			/*
			 * Lost the file, in chroot?
			 * Don't trash settings
			 */
			if (timespecisset(&dns_stat_resolv))
				return 0;
		}
	} else
		dns_rechktime = time(NULL) + dns_chktime;

	/* read the config file */
	if ((fp = fopen(_PATH_RESCONF, "r")) == NULL)
		return -1;

#define MATCH(line, name)						\
	(strncmp(line, name, sizeof(name) - 1) == 0	\
	 &&	(line[sizeof(name) - 1] == ' '			\
		 ||	line[sizeof(name) - 1] == '\t'))

	while ((line = fparseln(fp, &len, &lno, NULL, 0)) != NULL) {
		/* catch semicolon commenting */
		if ((s = strpbrk(line, ";")))
			*s = '\0';
		/* we ignore anything but nameserver */
		if (MATCH(line, "nameserver")) {
			struct addrinfo hints, *res;
			char pbuf[NI_MAXSERV];
			struct sockaddr_storage ss;
			struct sockaddr_in *sin4;
			struct sockaddr_in6 *sin6;

			s = line + sizeof("nameserver") - 1;
			while (*s == ' ' || *s == '\t')
				s++;
			if (*s == '\0') {
				free(line);
				continue;
			}

			memset(&hints, 0, sizeof(hints));
			hints.ai_flags = AI_NUMERICHOST;
			hints.ai_socktype = SOCK_DGRAM;	/* dummy */
			snprintf(pbuf, sizeof(pbuf), "%u", NAMESERVER_PORT);
			res = NULL;
			if (getaddrinfo(s, pbuf, &hints, &res) == 0 &&
					res->ai_next == NULL) {
				if (res->ai_family == AF_INET6) {
					sin6 = (struct sockaddr_in6 *)&ss;
					sin6->sin6_len = sizeof(struct sockaddr_in6);
					sin6->sin6_family = AF_INET6;
					sin6->sin6_port = htons(NAMESERVER_PORT);
					if (res->ai_addrlen <= sizeof(struct sockaddr_in6))
						memcpy(sin6, res->ai_addr, res->ai_addrlen);
					else
						memset(sin6, 0, sizeof(struct sockaddr_in6));
				} else if (res->ai_family == AF_INET) {
					sin4 = (struct sockaddr_in *)&ss;
					sin4->sin_len = sizeof(struct sockaddr_in);
					sin4->sin_family = AF_INET;
					sin4->sin_port = htons(NAMESERVER_PORT);
					if (res->ai_addrlen <= sizeof(struct sockaddr_in))
						memcpy(sin4, res->ai_addr, res->ai_addrlen);
					else
						memset(sin4, 0, sizeof(struct sockaddr_in));
				}
				dns_add_nameserver((struct sockaddr *)&ss);
			}
			if (res)
				freeaddrinfo(res);
		}
		free(line);
	}
	fclose(fp);
	return 0;
}

int
dns_init(void)
{
	static int called;

	if (!dns_retrans)
		dns_retrans = RES_TIMEOUT;
	if (!dns_retry)
		dns_retry = 4;
	if (!(dns_options & RES_INIT))
		dns_options = RES_DEFAULT;

	/* XXX */
	//dns_options |= RES_USEVC;
	
	/*
	 * Only the first init clears servers and timers.  Subsequent cause recheck of
	 * resolv.conf (if accessible), but will not destroy existing info.
	 */
	if (!called) {
		called = 1;

		TAILQ_INIT(&dns_servers);
		timespecclear(&dns_stat_resolv);
	}
	dns_rechktime = 0;

	dns_check_resolvconf(0);

	return 0;
}

static struct dns_query *
dns_newq(void)
{
	struct dns_query *q;

	if ((q = calloc(1, sizeof(struct dns_query))) == NULL)
		return NULL;

	TAILQ_INIT(&q->q_question);
	TAILQ_INIT(&q->q_answer);
	TAILQ_INIT(&q->q_authority);
	TAILQ_INIT(&q->q_additional);

	return q;
}

static void
dns_destroy(struct dns_query **q)
{
	struct dns_data *d;

	if (!q || !*q)
		return;

	if ((*q)->querybuf)
		free((*q)->querybuf);

	while ((d = TAILQ_FIRST(&(*q)->q_question))) {
		TAILQ_REMOVE(&(*q)->q_question, d, entry);
		free(d);
	}
	while ((d = TAILQ_FIRST(&(*q)->q_answer))) {
		TAILQ_REMOVE(&(*q)->q_answer, d, entry);
		free(d);
	}
	while ((d = TAILQ_FIRST(&(*q)->q_authority))) {
		TAILQ_REMOVE(&(*q)->q_authority, d, entry);
		free(d);
	}
	while ((d = TAILQ_FIRST(&(*q)->q_additional))) {
		TAILQ_REMOVE(&(*q)->q_additional, d, entry);
		free(d);
	}

	free(*q);
	*q = NULL;
}

static int
dns_query(const char *name, int class, int type, struct dns_query *q)
{
	HEADER *hp = (HEADER *)dns_qbuf;
	int n;

	if (!q)
		return -1;

	hp->rcode = NOERROR;	/* default */

	n = dns_mkquery(QUERY, name, class, type, NULL, 0,
			dns_qbuf, sizeof(dns_qbuf));
	if (n > 0 && ((dns_options & RES_USE_EDNS0)
				|| (dns_options & RES_USE_DNSSEC)))
		n = dns_opt(n, dns_qbuf, sizeof(dns_qbuf), sizeof(dns_qbuf));
	if (n <= 0) {
		h_errno = NO_RECOVERY;
		q->q_errno = EAI_FAIL;
		return n;
	}

	if (q->querybuf) {
		free(q->querybuf);
		q->querybuf = NULL;
	}

	/*
	 * The message is prefixed with a two byte length field which gives the
	 * message length, excluding the two byte length field
	 */
	if ((q->querybuf = calloc(1, n + 2)) == NULL) {
		q->q_errno = EAI_MEMORY;
		errno = ENOMEM;
		return -1;
	}
	q->query = q->querybuf + 2;

	/* set the length, for tcp messaging */
	*(uint16_t *)q->querybuf = htons(n);

	/* id stays in network byte order */
	q->id = hp->id;
	q->trys = 0;

	if ((dns_options & RES_USEVC) || n > PACKETSZ)
		q->mode = DNS_MODE_TCP;
	else
		q->mode = DNS_MODE_UDP;
	
	/* q->server set automagically by dns_send */
	q->qlen = n;
	memcpy(q->query, dns_qbuf, q->qlen);

	dns_send(q, 0);

	return n;
}

/*
 * event handler
 */
static void
dns_process(int fd, short which, void *arg)
{
	struct dns_nameserver *ns = arg;
	socklen_t len;
	struct timeval tv;
	struct event *evw, *evr;
	int n, dnsmode = 0;
	int *mode, *efd;
	struct dns_query *q = NULL, *qprev;
	time_t now, minttl;

	tv.tv_usec = 0;
	tv.tv_sec = minttl = dns_retrans;
	now = time(NULL);

#ifdef DEBUG_DNS
	log_debug("dns_process (%s%s%s) [%d]",
			(which & EV_READ) ? "R" : " ",
			(which & EV_WRITE) ? "W" : " ",
			(which & EV_TIMEOUT) ? "T" : " ",
			fd);
#endif

	/* select our current event */
	if (fd == ns->tcp.fd) {
		evw = &ns->tcp.evw;
		evr = &ns->tcp.evr;
		mode = &ns->tcp.mode;
		efd = &ns->tcp.fd;
		dnsmode = DNS_MODE_TCP;
	} else if (fd == ns->udp.fd) {
		evw = &ns->udp.evw;
		evr = &ns->udp.evr;
		mode = &ns->udp.mode;
		efd = &ns->udp.fd;
		dnsmode = DNS_MODE_UDP;
	} else {
		/* Data came in on an unknown socket.  Shut it down. */
		log_warnx("dns_process called on unregistered fd %d for %s, closing",
				fd, DNS_EVTYPE(which));
		//q->q_errno = EAI_SYSTEM;
		shutdown(fd, SHUT_RDWR);
		close(fd);
		return;
	}

	/*
	 * WRITE
	 */
	if (which & EV_WRITE) {

		/* still trying to connect? */
		if (*mode == DNS_MODE_CONNECT) {

			len = ns->ss.ss_len;
			if (connect(fd, (struct sockaddr *)&ns->ss, len) == -1) {
				if (errno != EINPROGRESS && errno != EINTR) {
					log_warn("dns connect to %s",
							log_sockaddr((struct sockaddr *)&ns->ss));
					close(fd);
					goto timeout;
				}

				/* schedule a new write */
				if (!event_pending(evw, EV_WRITE, NULL))
					event_add(evw, &tv);

				return;
			}

#if 0
			/* finally connected */
			log_debug("CONNECTED to [%s] ... now do something",
					log_sockaddr((struct sockaddr *)&ns->ss));
#endif

			*mode = DNS_MODE_NONE;

			/* FALLTHROUGH fastpath */
		}

		/* iterate through */
		TAILQ_FOREACH(q, &ns->qq, entry) {
			size_t wlen = 0;

			if (q->sent)
				continue;

			if (q->mode == DNS_MODE_UDP) {
				wlen = q->qlen;
				q->query = q->querybuf + 2;
			} else if (q->mode == DNS_MODE_TCP) {
				wlen = q->qlen + 2;
				q->query = q->querybuf;
			} else {
				/* this will cause a 0-byte write */
				q->q_errno = EAI_ADDRFAMILY;
				log_warnx("invalid qmode %d", q->mode);
			}

			if ((n = write(fd, q->query, wlen)) == -1) {
				if (errno == EAGAIN || errno == EINTR) {
					/* reschedule */
					event_add(evw, &tv);
					return;
				}
				log_warn("write failure qid %u to %s",
						q->id, log_sockaddr((struct sockaddr *)&ns->ss));
				continue;
			}

#if 0
			log_debug("DNS WRITE %d bytes", n);
			log_hexdump(q->query, n);
#endif

			q->sent = 1;

			/* make sure the read event exists */
			if (!event_pending(evr, EV_READ, NULL))
				event_add(evr, &tv);
		}
	} 
	
	/*
	 * READ
	 */
	if (which & EV_READ) {
		HEADER *hp;
		uint16_t plen = 0;
		unsigned char *p;

		if ((n = read(fd, dns_qbuf, sizeof(dns_qbuf))) == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return;
			log_warn("read failure from %s",
					log_sockaddr((struct sockaddr *)&ns->ss));
			goto timeout;
		}

		/* EOF */
		if (n == 0) {
			log_warnx("dns EOF on socket %d", fd);
			shutdown(fd, SHUT_RDWR);
			close(fd);
			goto timeout;
		}

#if 0
		log_debug("DNS READ %d bytes", n);
		log_hexdump(dns_qbuf, n);
#endif

		/* sanity */
		if (n < HFIXEDSZ) {
			log_debug("truncated response, tossing (%d < %d)", n, HFIXEDSZ);
			return;
		}

		/* packet iteration */
		p = dns_qbuf;
		while (p < (dns_qbuf + n)) {
			/* TCP comes in a STREAM, UDP in a packet */
			if (dnsmode == DNS_MODE_TCP) {
				plen = ntohs(*(uint16_t *)p);
				p += 2;
				hp = (HEADER *)(p);
			} else {
				plen = n;
				hp = (HEADER *)p;
			}

			if (p > (dns_qbuf + n)) {
				log_warnx("possible spoofed packet");
				break;
			}

			if ((p + plen) > (dns_qbuf + n)) {
				log_warnx("XXXXXX truncated packet");
				break;
			}

#ifdef DEBUG_DNS
			log_debug("searching resp id %d", hp->id);
#endif

			/* search for the packet in this server's q */
			for (q = TAILQ_FIRST(&ns->qq); q;) {
				if (q->id != hp->id) {
					q = TAILQ_NEXT(q, entry);
					continue;
				}

				/* truncated message, requery with tcp */
				if (hp->tc) {
					log_debug("DNS reply %u truncated, requerying TCP", q->id);
					q->mode = DNS_MODE_TCP;

					if (dns_send(q, 0) == -1) {
						log_debug("FAILED requeuing truncated response");
						if (q->callback)
							q->callback(q, q->callback_arg);

						dns_destroy(&q);
						q = NULL;	/* just because */
					}
					break;
				}

				/* parse */
				if (dns_parse(q, p, plen) == -1)
					log_debug("parse error qid %u", q->id);

				if (q->callback)
					q->callback(q, q->callback_arg);

				qprev = TAILQ_PREV(q, dns_query_list, entry);
				TAILQ_REMOVE(&ns->qq, q, entry);
				dns_destroy(&q);
				q = NULL;

				break;
			}
			/* advance by packet length */
			p += plen;
		}
	}

timeout:
	/*
	 * TIMEOUT checking.  This scans after successful i/o for ttl violations
	 * It is also messy, since elements may be removed
	 */
	for (q = TAILQ_FIRST(&ns->qq); q;) {
#if 0
		log_debug("---> checking %d ttl %d", q->id, (q->ttl - now));
#endif
		if (q->ttl > now) {
			if ((q->ttl - now) < minttl)
				minttl = q->ttl - now;

			q = TAILQ_NEXT(q, entry);
			continue;
		}

		/*
		 * dns_send modifies the queue structure, we will back up one
		 * element, and then move forward.
		 *
		 * If it fails, it will have set q->errno, so call the handler
		 */
		qprev = TAILQ_PREV(q, dns_query_list, entry);
		if (dns_send(q, 1) == -1) {
			log_debug("dns_send FAILED");
			if (q->callback)
				q->callback(q, q->callback_arg);

			dns_destroy(&q);
			q = NULL;
		}

		/* break out if this was the only element */
		if ((q = qprev) == NULL) {
			if ((q = TAILQ_FIRST(&ns->qq)) == NULL)
				break;
			continue;
		}

		q = TAILQ_NEXT(q, entry);
	}

	/* reschedule the timeout to (minttl) seconds */
	if (event_pending(evr, EV_READ, &tv)) {
		if (tv.tv_sec != minttl) {
			tv.tv_usec = 0;
			tv.tv_sec = minttl;
			event_del(evr);
			event_add(evr, &tv);
		}
	}

	if (which & EV_TIMEOUT) {
		/*
		 * if nothing is queued, and we have hit the timeout, close down the
		 * connection.  This gives us a connection life of (dns_retrans)
		 * seconds without a new query before shutdown.
		 */
		if (TAILQ_EMPTY(&ns->qq)) {
			if (event_pending(evw, EV_WRITE, NULL))
				event_del(evw);
			if (event_pending(evr, EV_READ, NULL))
				event_del(evr);
			/* ignore errors */
			shutdown(*efd, SHUT_RDWR);
			close(*efd);
			*efd = -1;
		} else
			event_add(evr, &tv);
	}

	return;
}

/*
 * send is a misnomer, it just queues it for sending
 * XXX WARNING XXX
 * This code moves a query from one queue to another.  If this is called from
 * within a TAILQ_FOREACH, care must be taken to (q = qprev) after dns_send()
 * to prevent early loop termination, or 'jumping the queue'
 */
static int
dns_send(struct dns_query *q, int advance)
{
	struct sockaddr *sa;
	int s;
	struct timeval tv;

	tv.tv_usec = 0;
	tv.tv_sec = dns_retrans;

#ifdef DEBUG_DNS
	log_debug("dns_send advance=%d server=%s trys=%d", advance,
			q->server ? log_sockaddr((struct sockaddr *)&q->server->ss)
			: "NONE", q->trys);
#endif

	/* pick the next server */
	if (advance) {
		/* remove from the old server's purview */
		TAILQ_REMOVE(&q->server->qq, q, entry);
		q->server = TAILQ_NEXT(q->server, entry);
	} else {
		if (q->server == NULL) {
			q->server = TAILQ_FIRST(&dns_servers);
		} else {
			/* leave the server the same for re-queue */
			q->trys++;
			TAILQ_REMOVE(&q->server->qq, q, entry);
		}
	}

	/* null the q entry, better to abort a FOREACH than to loop forever */
	memset(&q->entry, 0, sizeof(q->entry));

	/* ran out of servers */
	if (q->server == TAILQ_END(&dns_servers)) {
		q->trys++;

		if (q->trys > dns_retry || TAILQ_EMPTY(&dns_servers)) {
			/* if no other error, give a timeout error */
			if (!q->q_errno)
				q->q_errno = EAI_AGAIN;

			return -1;
		}

		q->server = TAILQ_FIRST(&dns_servers);
	}

#if 0
	log_debug("dns_send queueing server %s id %d",
			log_sockaddr((struct sockaddr *)&q->server->ss), q->id);
#endif

	/* push into this server's purview */
	q->sent = 0;
	q->ttl = time(NULL) + dns_retrans;

	/*
	 * mess with the sockets, since they are automagically cleaned up
	 * when queries run out
	 */
	if (q->mode == DNS_MODE_UDP) {

		/* no socket */
		if (q->server->udp.fd == -1) {
			sa = (struct sockaddr *)&q->server->ss;
			if ((s = socket(sa->sa_family, SOCK_DGRAM, 0)) < 0) {
				log_warn("udp socket");
				q->q_errno = EAI_SYSTEM;
				return -1;
			}

			if (fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK) == -1) {
				log_warn("udp nonblock");
				q->q_errno = EAI_SYSTEM;
				close(s);
				return -1;
			}

			/* switch mode to connect, trigger a write wait */

			q->server->udp.mode = DNS_MODE_CONNECT;
			q->server->udp.fd = s;

			/* only add the write event for now */
			event_set(&q->server->udp.evw, s, EV_WRITE, dns_process, q->server);
			event_set(&q->server->udp.evr, s, EV_READ|EV_PERSIST, dns_process,
					q->server);
		}

		/* we gots stuff to writes */
		if (!event_pending(&q->server->udp.evw, EV_WRITE, NULL))
			event_add(&q->server->udp.evw, &tv);

	} else if (q->mode == DNS_MODE_TCP) {

		if (q->server->tcp.fd == -1) {
			sa = (struct sockaddr *)&q->server->ss;
			if ((s = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
				log_warn("tcp socket");
				q->q_errno = EAI_SYSTEM;
				return -1;
			}

			if (fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK) == -1) {
				log_warn("tcp nonblock");
				q->q_errno = EAI_SYSTEM;
				close(s);
				return -1;
			}

			/* switch mode to connect, trigger a write wait */
			if (connect(s, sa, sa->sa_len) == -1) {
				if (errno != EINPROGRESS && errno != EINTR) {
					log_warn("tcp connect to %s", log_sockaddr(sa));
					q->q_errno = EAI_SYSTEM;
					close(s);
					return -1;
				}

				/*
				 * do not set DNS_MODE_CONNECT, tcp connect can only be
				 * called once
				 */
				q->server->tcp.fd = s;

				event_set(&q->server->tcp.evw, s, EV_WRITE, dns_process,
						q->server);
				event_set(&q->server->tcp.evr, s, EV_READ|EV_PERSIST,
						dns_process, q->server);
			}
		}

		/* we gots stuff to writes */
		if (!event_pending(&q->server->tcp.evw, EV_WRITE, NULL))
			event_add(&q->server->tcp.evw, &tv);

	} else {
		log_debug("unknown query mode");
		q->q_errno = EAI_ADDRFAMILY;
		return -1;
	}

	q->q_errno = 0;
	/* only push the query onto the stack when a connection is sure */
	TAILQ_INSERT_TAIL(&q->server->qq, q, entry);

	return 0;
}

/*
 * HEADER
 *                               1  1  1  1  1  1
 * 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
/*
 * QUESTION
 *                               1  1  1  1  1  1
 * 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                     QNAME                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QTYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     QCLASS                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
static int
dns_mkquery(int op, const char *dname, int class, int type,
		const unsigned char *data, int datalen,
		unsigned char *buf, int buflen)
{
	HEADER *hp;
	unsigned char *cp, *ep;
	unsigned char *dnptrs[20], **dpp, **lastdnptr;
	int n;

	if ((buf == NULL) || (buflen < HFIXEDSZ))
		return -1;

	bzero(buf, HFIXEDSZ);
	hp = (HEADER *)buf;

	/* built in resolver uses res_randomid() */
	hp->id = htons(arc4random());

	hp->opcode = op;

	/* recursion desired */
	hp->rd = (dns_options & RES_RECURSE) != 0;
	hp->rcode = NOERROR;

	cp = buf + HFIXEDSZ;
	ep = buf + buflen;
	dpp = dnptrs;
	*dpp++ = buf;
	*dpp++ = NULL;
	lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);

	switch (op) {
		case QUERY:
			/* FALLTHROUGH */
		case NS_NOTIFY_OP:
			if (ep - cp < QFIXEDSZ)
				return -1;
			if ((n = dn_comp(dname, cp, ep - cp - QFIXEDSZ, dnptrs,
							lastdnptr)) < 0)
				return -1;
			cp += n;
			PUTSHORT(type, cp);
			PUTSHORT(class, cp);
			hp->qdcount = htons(1);
			if (op == QUERY || data == NULL)
				break;
			/*
			 * Make an additional record for completion domain
			 */
			if (ep - cp < RRFIXEDSZ)
				return -1;
			if ((n = dn_comp(data, cp, ep - cp - RRFIXEDSZ, dnptrs,
					lastdnptr)) < 0)
				return -1;
			cp += n;
			PUTSHORT(T_NULL, cp);
			PUTSHORT(class, cp);
			PUTLONG(0, cp);
			PUTSHORT(0, cp);
			hp->arcount = htons(1);
			break;

		case IQUERY:
			/*
			 * Initialize answer section
			 */
			if (ep - cp < 1 + RRFIXEDSZ + datalen)
				return -1;
			*cp++ = '\0';	/* no domain name */
			PUTSHORT(type, cp);
			PUTSHORT(class, cp);
			PUTLONG(0, cp);
			PUTSHORT(datalen, cp);
			if (datalen) {
				bcopy(data, cp, datalen);
				cp += datalen;
			}
			hp->ancount = htons(1);
			break;

		default:
			return -1;
	}
	return (cp - buf);
}

static int
dns_opt(int n0, unsigned char *buf, int buflen, int anslen)
{
	HEADER *hp;
	unsigned char *cp, *ep;
	short tmp;

	hp = (HEADER *)buf;
	cp = buf + n0;
	ep = buf + buflen;

	if (ep - cp < 1 + RRFIXEDSZ)
		return -1;

	*cp++ = 0;						/* "." */

	PUTSHORT(T_OPT, cp);			/* TYPE */
	if (anslen > 0xFFFF)
		anslen = 0xFFFF;			/* limit to 16bit value */
	PUTSHORT(anslen & 0xFFFF, cp);	/* CLASS = UDP payload site */
	*cp++ = NOERROR;				/* extended RCODE */
	*cp++ = 0;						/* EDNS version */

	if (dns_options & RES_USE_DNSSEC) {
		PUTSHORT(DNS_MESSAGEEXTFLAG_DO, cp);
	} else {
		PUTSHORT(0, cp);
	}
	PUTSHORT(0, cp);				/* RDLEN */

	tmp = ntohs(hp->arcount);
	hp->arcount = htons(tmp + 1);

	return cp - buf;
}

/*
 * HEADER
 *                               1  1  1  1  1  1
 * 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
/*
 * RESOURCE RECORD
 *                               1  1  1  1  1  1
 * 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                                               |
 * /                                               /
 * /                      NAME                     /
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TYPE                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                     CLASS                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      TTL                      |
 * |                                               |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                   RDLENGTH                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 * /                     RDATA                     /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

static int
dns_parse_qsection(struct dns_data_list *dl, int count,
		unsigned char *cp, const unsigned char *ans, size_t anslen)
{
	int i, length;
	struct dns_data *d;
	unsigned char *p = cp;

	for (i = 0; i < count; i++) {
		if ((d = calloc(1, sizeof(struct dns_data))) == NULL)
			return EAI_MEMORY;

		if ((length = dn_expand(ans, ans + anslen, p, d->name,
						sizeof(d->name))) == -1)
			return EAI_FAIL;

		p += length;
		GETSHORT(d->type, p);
		GETSHORT(d->class, p);

		TAILQ_INSERT_TAIL(dl, d, entry);

#ifdef DEBUG_DNS
		log_debug("   DNS qsection: %d/%d (%s)", d->type, d->class, d->name);
#endif
	}

	return (p - cp);
}

static int
dns_parse_rrsection(struct dns_data_list *dl, int count, unsigned char *cp,
		const unsigned char *ans, size_t anslen)
{
	int i, length, rsize;
	struct dns_data *d;
	uint32_t num;
	unsigned char *p = cp;

	for (i = 0; i < count; ++i) {

		if ((d = calloc(1, sizeof(struct dns_data))) == NULL)
			return EAI_MEMORY;

		if ((length = dn_expand(ans, ans + anslen, p,
						d->name, sizeof(d->name))) == -1) {
			log_debug("  DNS rrsection failed on name");
			free(d);
			return EAI_FAIL;
		}
		p += length;

		GETSHORT(d->type, p);
		GETSHORT(d->class, p);
		GETLONG(d->ttl, p);
		GETSHORT(rsize, p);

#ifdef DEBUG_DNS
		log_debug("   DNS rrsection: %d/%d ttl %u size %d (%s)",
				d->type, d->class, d->ttl, rsize, d->name);
#endif

#define DN_EXPAND(name, size) do {									\
		length = dn_expand(ans, ans + anslen, p, (name), (size));	\
		if (length == -1) {											\
			log_debug("  DNS rrsection failed on rrdata");			\
			free(d);												\
			return EAI_FAIL;										\
		} else														\
			p += length;											\
	} while(0);
		
		switch (d->type) {
			case T_MX:
				GETSHORT(d->data.mx.pref, p);
				DN_EXPAND(d->data.mx.name, sizeof(d->data.mx.name));
				break;
			case T_NS:
				DN_EXPAND(d->data.ns.name, sizeof(d->data.ns.name));
				break;
			case T_CNAME:
				DN_EXPAND(d->data.cname.name, sizeof(d->data.cname.name));
				break;
			case T_PTR:
				DN_EXPAND(d->data.ptr.name, sizeof(d->data.ptr.name));
				break;
			case T_SOA:
				DN_EXPAND(d->data.soa.mname, sizeof(d->data.soa.mname));
				DN_EXPAND(d->data.soa.rname, sizeof(d->data.soa.rname));
				GETLONG(d->data.soa.serial, p);
				GETLONG(d->data.soa.refresh, p);
				GETLONG(d->data.soa.retry, p);
				GETLONG(d->data.soa.expire, p);
				GETLONG(d->data.soa.minimum, p);
				break;
			case T_TXT:
				//DN_EXPAND(d->data.txt.data, sizeof(d->data.txt.data));
				memcpy(d->data.txt.data, (p + 1), (rsize - 1));
				p += rsize;
				break;
			case T_A:
				d->data.a.ss.ss_len = sizeof(struct sockaddr_in);
				d->data.a.ss.ss_family = AF_INET;
				GETLONG(num, p);
				((struct sockaddr_in *)&d->data.a.ss)->sin_addr.s_addr = ntohl(num);
				break;
			case T_AAAA:
				d->data.a.ss.ss_len = sizeof(struct sockaddr_in6);
				d->data.a.ss.ss_family = AF_INET6;
				GETLONG(num, p);
				((struct sockaddr_in6 *)&d->data.a.ss)->sin6_addr.__u6_addr.__u6_addr32[0] = ntohl(num);
				GETLONG(num, p);
				((struct sockaddr_in6 *)&d->data.a.ss)->sin6_addr.__u6_addr.__u6_addr32[1] = ntohl(num);
				GETLONG(num, p);
				((struct sockaddr_in6 *)&d->data.a.ss)->sin6_addr.__u6_addr.__u6_addr32[2] = ntohl(num);
				GETLONG(num, p);
				((struct sockaddr_in6 *)&d->data.a.ss)->sin6_addr.__u6_addr.__u6_addr32[3] = ntohl(num);
				break;
			case T_SRV:
				GETSHORT(d->data.srv.priority, p);
				GETSHORT(d->data.srv.weight, p);
				GETSHORT(d->data.srv.port, p);
				DN_EXPAND(d->data.srv.name, sizeof(d->data.srv.name));
				break;
			default:
				log_warnx("query type %d not yet implemented", d->type);
				free(d);
				return -1;
		}
#undef DN_EXPAND

		TAILQ_INSERT_TAIL(dl, d, entry);
	}

	return (p - cp);
}

static int
dns_parse(struct dns_query *q, unsigned char *ans, size_t anslen)
{
	HEADER *hp = (HEADER *)ans;
	unsigned char *cp = ans;
	int e;

//	log_debug("XXX dns_parse qid=%u", q->id);

	if (anslen < HFIXEDSZ)
		return -1;

	cp += HFIXEDSZ;

	if (hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
#if 0
		log_debug("DNS failure: rcode=%u ancount=%u", hp->rcode,
				ntohs(hp->ancount));
#endif

		switch (hp->rcode) {
			case NXDOMAIN:
				q->q_errno = EAI_NONAME;
				break;
			case SERVFAIL:
				q->q_errno = EAI_AGAIN;
				break;
			case NOERROR:
				q->q_errno = EAI_NODATA;
				break;
			case FORMERR:
			case NOTIMP:
			case REFUSED:
			default:
				q->q_errno = EAI_FAIL;
				break;
		}
	}

	/* there must be at least one query */
	if (ntohs(hp->qdcount) < 1) {
		q->q_errno = EAI_NODATA;
		return 0;
	}

	/* parse query section */
	if ((e = dns_parse_qsection(&q->q_question, ntohs(hp->qdcount), cp, ans,
					anslen)) <= -1) {
		q->q_errno = e;
		log_debug("parsing qsection: %s", gai_strerror(q->q_errno));
		return -1;
	} else
		cp += e;

	/* parse answer section */
	if ((e = dns_parse_rrsection(&q->q_answer, ntohs(hp->ancount), cp, ans,
					anslen)) <= -1) {
		q->q_errno = e;
		log_debug("parsing ansection: %s", gai_strerror(q->q_errno));
		return -1;
	} else
		cp += e;

	/* parse authority section */
	if ((e = dns_parse_rrsection(&q->q_authority, ntohs(hp->nscount), cp, ans,
					anslen)) <= -1) {
		q->q_errno = e;
		log_debug("parsing nssection: %s", gai_strerror(q->q_errno));
		return -1;
	} else
		cp += e;

	/* parse additional section */
	if ((e = dns_parse_rrsection(&q->q_additional, ntohs(hp->arcount), cp,
					ans, anslen)) <= -1) {
		q->q_errno = e;
		log_debug("parsing arsection: %s", gai_strerror(q->q_errno));
		return -1;
	} else
		cp += e;

	return 0;
}

int
dns_mux(const char *name, int type,
		void (*callback)(struct dns_query *, void *), void *arg)
{
	struct dns_query *q;
	int n;

	if ((q = dns_newq()) == NULL)
		return -1;

	q->callback = callback;
	q->callback_arg = arg;

	n = dns_query(name, C_IN, type, q);

	if (n == -1)
		return -1;

	return 0;
}

/* uses dns_qbuf */
int
dns_rptr(struct sockaddr *sa,
		void (*callback)(struct dns_query *, void *), void *arg)
{
	char buf[NI_MAXHOST];
	char *b;
	char sep[2] = {0, 0};

	if (sa->sa_family == AF_INET)
		sep[0] = '.';
	else if (sa->sa_family == AF_INET6) {
		/* XXX not yet implemented */
		sep[0] = ':';
		errno = EAFNOSUPPORT;
		return -1;
	} else
		return -1;

	if (getnameinfo(sa, sa->sa_len, buf, sizeof(buf), NULL, 0,
				NI_NUMERICHOST))
		return -1;

	strlcpy(dns_hbuf, "", sizeof(dns_hbuf));
	while ((b = strrchr(buf, sep[0]))) {
		strlcat(dns_hbuf, b+1, sizeof(dns_hbuf));
		strlcat(dns_hbuf, sep, sizeof(dns_hbuf));
		*b = '\0';
	}
	strlcat(dns_hbuf, buf, sizeof(dns_hbuf));
	strlcat(dns_hbuf, ".in-addr.arpa.", sizeof(dns_hbuf));

	return dns_mux(dns_hbuf, T_PTR, callback, arg);
}

/*
 * Disable callback/arg only, do not destroy the query
 */
void
dns_abort_byarg(void *arg)
{
	struct dns_nameserver *ns;
	struct dns_query *q;

	TAILQ_FOREACH(ns, &dns_servers, entry)
		TAILQ_FOREACH(q, &ns->qq, entry)
			if (q->callback_arg == arg) {
				q->callback = NULL;
				q->callback_arg = NULL;
			}
}
