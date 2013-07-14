/* $Gateweaver: robin_connect.c,v 1.49 2007/01/31 18:25:29 cmaxwell Exp $ */
/*
 * Copyright (c) 2005 Christopher Maxwell.  All rights reserved.
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "robin_locl.h"
#include <toolbox_asn1_der.h>

#ifndef lint
RCSID("$Gateweaver: robin_connect.c,v 1.49 2007/01/31 18:25:29 cmaxwell Exp $");
#endif

/*
 * CONNECT, a.k.a. INTERNAL PROCESSOR
 * ==================================
 *
 * 	1a.	Provide a simple interface to connect to cell or host.  Once connected,
 * 		the CONNECT ENGINE callback is executed.  
 *
 * 	1b.	Once authenticated, the ACCEPT ENGINE callback is executed.
 *
 * 	2.	Decode all known message types.  There is currently no way to deal with
 * 		unknown messages.  Messages are then sent individually to the PROCESS
 * 		ENGINE for further action.  If the ENGINE is not enabled, the EXTERNAL
 * 		processor will be called instead.
 *
 * 	3.	Notice shutdown of the pigeon connection, and translate error messages
 * 		to forms the API understands.  Then trigger the ENGINE/EXTERNAL
 * 		shutdown routines.
 */

/*
 * INTERNAL callback mechanism.  Fallback from ENGINE->EXTERNAL->LOG.  Should
 * only be called AFTER all connections have failed, or the connection timer
 * runs out.
 *
 * Type, ConTeXt, Con, Ret
 */
#define CALLBACK_INTERNAL(T, CTX, C, R) do {			\
	if ((CTX)->cb.T)									\
		(CTX)->cb.T((CTX), (C), (R), (CTX)->cb.arg);	\
	else if ((C)->cb.T)								\
		(C)->cb.T((CTX), (C), (R), (C)->cb.arg);		\
	else												\
		log_debug("CALLBACK_INTERNAL no callback");		\
} while (0)

/*
 * IN_DNS is used to mask late dns errors from calling the connect callback
 * while a connection is either in-progress or running
 */
#define IN_DNS(state) \
	((state) != CONNECT_ING && (state) != CONNECT_ED)

static void lookup_dnscb(struct dns_query *, void *);
static int lookup_dns(robin_con, int);
static int socket_connect(robin_con, unsigned int, unsigned int);

/* INTERNAL PROCESSORS */
static void robin_do_accept(struct pigeon *, void *);
static void robin_do_accept_server(struct pigeon *, void *);
static void robin_do_shutdown(struct pigeon *, void *);

static void
callback_connect(robin_context ctx, robin_con con, int ret)
{
	if (ctx->cb.connect)
		ctx->cb.connect(ctx, con, ret, ctx->cb.arg);
	else if (con->cb.connect)
		con->cb.connect(ctx, con, ret, con->cb.arg);
	else
		log_debug("callback_connect: no callback");
}

static void
lookup_dnscb(struct dns_query *q, void *arg)
{
	robin_con con = arg;
	struct dns_data *dq, *da;
	int ret, additional = 0;
	RobinHost *host = NULL;

	if (con == NULL)
		fatalx("robin connect lost arguments during dns query");

	con->connect.nsqueries--;

	/*
	 * TIMEOUT is checked early on error, but late on success.  This is a
	 * feature, not a bug.
	 */
	dq = TAILQ_FIRST(&q->q_question);

	if (robin_verbose & ROBIN_LOG_CONNECT) {
		char *s = "";
		if (dq != TAILQ_END(&q->q_question))
			s = dq->name;
		log_debug("==] CON %p dnscb nsq=%u q=%s", con,
				con->connect.nsqueries, s);
	}

	if (q->q_errno) {
		char *qhost = NULL;

		/* FAILED, and something else marked us timed out */
		if (con->connect.state == CONNECT_TIMEDOUT) {
			if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
				callback_connect(con->context, con, ROBIN_TIMEOUT);
			return;
		}

		/* temporary failure, try again until timeout */
		if (q->q_errno == EAI_AGAIN) {
			if ((ret = lookup_dns(con, 1)))
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ret);
			return;
		}

		/* host lookup failed, no recovery possible */
		if (con->connect.state == CONNECT_LOOKUP_A) {
			if ((ret = lookup_dns(con, 1)))
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ROBIN_NOHOSTS);
			return;
		}

		/* somehow, we got connected before the querying finished */
		if (con->connect.state != CONNECT_LOOKUP_SRV)
			return;

		/* no SRV data, fallback to A/AAAA */
		if (q->q_errno == EAI_NONAME || q->q_errno == EAI_NODATA) {
			con->connect.state = CONNECT_LOOKUP_A;
			if ((ret = lookup_dns(con, 0)))
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ret);
			return;
		}

		if (dq != TAILQ_END(&q->q_question))
			qhost = dq->name;

		log_warnx("robin critical dns error querying \"%s\": %s",
				qhost, gai_strerror(q->q_errno));

		if ((ret = lookup_dns(con, 1)))
			if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
				callback_connect(con->context, con, ROBIN_NOHOSTS);
		return;
	}

	/* No question!  That's un-possible! */
	if (dq == TAILQ_END(&q->q_question)) {
		if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
			callback_connect(con->context, con, ROBIN_BADADDR);
		return;
	}


	TAILQ_FOREACH(dq, &q->q_answer, entry) {
		if (dq->type == T_SRV) {
			if (con->connect.state == CONNECT_LOOKUP_SRV)
				con->connect.state = CONNECT_LOOKUP_A;

			/* add hostname to our list */
			ret = robin_get_host(&con->connect.hosts, dq->data.srv.name, &host);
			if (ret == ROBIN_NOTFOUND) {
				ret = robin_add_hostname(&con->connect.hosts,
						dq->data.srv.name);
				if (ret == ROBIN_SUCCESS)
					ret = robin_get_host(&con->connect.hosts,
							dq->data.srv.name, &host);
			}
			if (ret != ROBIN_SUCCESS) {
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ret);
				return;
			}

			/* scan ADDITIONAL for addresses */
			TAILQ_FOREACH(da, &q->q_additional, entry) {
				if (da->type != T_A && da->type != T_AAAA)
					continue;
				if (strcasecmp(da->name, dq->data.srv.name) != 0)
					continue;

				/* slip the port into the sockaddr_storage */
				if (da->data.a.ss.ss_family == AF_INET)
					((struct sockaddr_in *)&da->data.a.ss)->sin_port
						= htons(dq->data.srv.port);
				else if (da->data.a.ss.ss_family == AF_INET6)
					((struct sockaddr_in6 *)&da->data.a.ss)->sin6_port
						= htons(dq->data.srv.port);

				if ((ret = robin_add_hostaddr(host,
								(struct sockaddr *)&da->data.a.ss)))
					continue;

				/* have to avoid re-querying */
				additional = 1;
			}

			/* no A/AAAA in the additional, query for A records */
			if (!additional && con->connect.state == CONNECT_LOOKUP_A) {
				if (dns_a(dq->data.srv.name, lookup_dnscb, con) == -1) {
					if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
						callback_connect(con->context, con, ROBIN_BADADDR);
					return;
				}
				con->connect.nsqueries++;
			}
		}

		if (dq->type == T_A || dq->type == T_AAAA) {
			/* add hostname to our list */
			ret = robin_get_host(&con->connect.hosts, dq->name, &host);
			if (ret == ROBIN_NOTFOUND) {
				ret = robin_add_hostname(&con->connect.hosts, dq->name);
				if (ret == ROBIN_SUCCESS)
					ret = robin_get_host(&con->connect.hosts, dq->name, &host);
			}
			if (ret != ROBIN_SUCCESS) {
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ret);
				return;
			}

			/* slip in the default port from the context */
			if (dq->data.a.ss.ss_family == AF_INET)
				((struct sockaddr_in *)&dq->data.a.ss)->sin_port
					= htons(con->context->con.port);
			else if (dq->data.a.ss.ss_family == AF_INET6)
				((struct sockaddr_in6 *)&dq->data.a.ss)->sin6_port
					= htons(con->context->con.port);

			/* and add the hostaddr */
			if ((ret = robin_add_hostaddr(host,
							(struct sockaddr *)&dq->data.a.ss))) {
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ret);
				return;
			}
		}

		if (dq->type != T_A && dq->type != T_AAAA && dq->type != T_SRV) {
			log_warnx("robin serious dns warning querying \"%s\": "
					"unexpected record type %d returned",
					dq->name, dq->type);
			if ((ret = lookup_dns(con, 1)))
				if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
					callback_connect(con->context, con, ROBIN_BADADDR);
			return;
		}
	}

	if ((ret = socket_connect(con, 0, 0))) {
		if (ret != ROBIN_NOHOSTS)
			log_debug("socket_connect failed in dnscb: %s",
					ret == ROBIN_SYSTEM
					? strerror(errno)
					: robin_print_error(con->context, ret));
		if (con->connect.nsqueries == 0 && IN_DNS(con->connect.state))
			callback_connect(con->context, con, ret);
	}
}

/*
 * Lookup through the hostnames
 */
static int
lookup_dns(robin_con con, int advance)
{
	if (con == NULL)
		return ROBIN_API_INVALID;
	if (con->connect.hosts.len == 0)
		return ROBIN_API_REQUIRED;
	if (con->connect.state != CONNECT_LOOKUP_SRV
			&& con->connect.state != CONNECT_LOOKUP_A)
		return ROBIN_INPROGRESS;

	//log_debug("lookup_dns advance=%d", advance);

	if (con->connect.hostindex >= con->connect.hosts.len)
		return ROBIN_NOHOSTS;

	/* absolutely must NEVER set hostindex out of range! */
	if (advance) {
		if ((con->connect.hostindex + 1) >= con->connect.hosts.len)
			return ROBIN_NOHOSTS;
		con->connect.hostindex++;
	}

	switch (con->connect.state) {
		case CONNECT_LOOKUP_SRV:
			if (dns_srv(con->connect.hosts.val[con->connect.hostindex].hostname,
						lookup_dnscb, con) == -1)
				return ROBIN_BADADDR;
			con->connect.nsqueries++;
			break;

		case CONNECT_LOOKUP_A:
			if (dns_a(con->connect.hosts.val[con->connect.hostindex].hostname,
						lookup_dnscb, con) == -1)
				return ROBIN_BADADDR;
			con->connect.nsqueries++;
			break;

		case CONNECT_ING:
		case CONNECT_ED:
		case CONNECT_FAIL:
		case CONNECT_TIMEDOUT:
			return ROBIN_API_BADSTATE;
	}

	return ROBIN_SUCCESS;
}

/*
 * Callback from raw socket connect() operation.
 */
static void
connect_evcb(int fd, short which, void *arg)
{
	robin_con con = arg;
	robin_context context = NULL;
	int ret = ROBIN_SUCCESS, err = 0;
	socklen_t errsz = sizeof(err);
	char servicehost[MAXHOSTNAMELEN];
	char hostbuf[MAXHOSTNAMELEN];
	const char *hostname;
	struct robin_state *s, *s_n;

	if (con == NULL)
		fatalx("connect_evcb failed");

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p connected fd=%d", con, fd);

	/* connection timed out, try again */
	if (which & EV_TIMEOUT) {
		log_debug("connect timeout, retrying");
		close(fd);
		goto out;
	}

	/* give us a temporary hostname to work with easily */
	if (con->connect.hosts.val &&
			con->connect.hosts.len > con->connect.hostindex &&
			con->connect.hosts.val[con->connect.hostindex].hostname)
		hostname = con->connect.hosts.val[con->connect.hostindex].hostname;
	else
		hostname = NULL;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errsz) == -1)
		err = errno;
	if (err) {
		log_debug("robin connect to %s (%s) failed: %s",
				hostname,
				robin_print_hostaddr(&con->connect.hosts
					.val[con->connect.hostindex].addresses
					.val[con->connect.addrindex]), strerror(err));
		close(fd);
		goto out;
	}
	con->connect.state = CONNECT_ED;

	/* breed a pigeon handler, with the INTERNAL PROCESSORS */
	if (con->cleartext)
		con->p = pigeon_breed_cleartext(fd,
				con->context->con.username,
				con->mode,
				robin_do_accept,
				robin_api_connect_process,
				robin_do_shutdown,
				con);
	else
		con->p = pigeon_breed(fd,
				con->context->con.username,
				con->mode,
				robin_do_accept,
				robin_api_connect_process,
				robin_do_shutdown,
				con);
	if (con->p == NULL) {
		log_warn("robin authenticating to %s failed", hostname);
		goto out;
	}

	if (con->context->con.ccache)
		if (pigeon_set_ccache(con->p, con->context->con.ccache))
			log_warn("robin could not access credential cache");

	ret = ROBIN_API_OVERFLOW;

	if (strlcpy(servicehost, con->context->con.servname, sizeof(servicehost))
			>= sizeof(servicehost))
		goto out;
	if (hostname == NULL) {
		/* client connection without hostname is probably an fd */
		if (con->mode == PIGEON_MODE_CLIENT && con->context->con.username &&
				*con->context->con.username) {
			if (strlcpy(servicehost, con->context->con.username,
						sizeof(servicehost)) >= sizeof(servicehost))
				goto out;
		} else {
			if (gethostname(hostbuf, sizeof(hostbuf)) == 0)
				hostname = hostbuf;
		}
	}
	if (hostname) {
		if (strlcat(servicehost, "@", sizeof(servicehost))
				>= sizeof(servicehost))
			goto out;
		if (strlcat(servicehost, hostname, sizeof(servicehost))
				>= sizeof(servicehost))
			goto out;
	}
	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p username %s servicehost %s",
				con, con->context->con.username, servicehost);

	if (pigeon_connect(con->p, servicehost) == -1) {
		ret = ROBIN_PIGEON;
		goto out;
	}

	return;

out:
	/* try again */
	if ((ret = socket_connect(con, con->connect.hostindex,
					con->connect.addrindex + 1)) == ROBIN_SUCCESS)
		return;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p failed, aborting", con);

	context = con->context;

	/* failed in a bad way, no way to recover */
	callback_connect(con->context, con, ret);

	/* abort all context state, nothing is going to work here */
	if (robin_valid_con(context, con) == ROBIN_SUCCESS) {
		for (s = TAILQ_FIRST(&con->context->state);
				s != TAILQ_END(&con->context->state);
				s = s_n) {
			s_n = TAILQ_NEXT(s, entry);
			robin_state_abort(s, ROBIN_DISCONNECTED);
		}

		/* now destroy the connection */
		robin_shutdown_con(context, con);
	}
}

static int
socket_connect(robin_con con, unsigned int hostindex, unsigned int addrindex)
{
	int ret, fd = -1;
	RobinHost *host;
	RobinHostAddress *addr;
	struct sockaddr_storage ss;
	struct timeval tv = { con->context->con.timeout, 0 };
	int bsize;
#if 0
	unsigned int i, j;

	log_warnx("got connect - %u hosts", con->connect.hosts.len);

	/* XXX debug print host + addr list */
	for (i = 0; i < con->connect.hosts.len; i++) {
		log_warnx("\t%s", con->connect.hosts.val[i].hostname);
		for (j = 0; j < con->connect.hosts.val[i].addresses.len; j++)
			log_warnx("\t\t%s", robin_print_hostaddr(&con->connect.hosts
						.val[i].addresses.val[j]));
	}
#endif

	con->connect.hostindex = hostindex;
	con->connect.addrindex = addrindex;

	if (con->connect.hostindex >= con->connect.hosts.len)
		return ROBIN_NOHOSTS;

	/*
	 * safely adjust the hostindex and addrindex.  addr may be set out-of-range
	 * to force a safe 'overflow' to the next host. 
	 */
	addr = NULL;
	for (; con->connect.hostindex < con->connect.hosts.len;
			con->connect.hostindex++) {
		host = &con->connect.hosts.val[con->connect.hostindex];
		for (; con->connect.addrindex < host->addresses.len;
				con->connect.addrindex++) {
			addr = &host->addresses.val[con->connect.addrindex];
			break;
		}
		if (addr)
			break;
		con->connect.addrindex = 0;
	}

	if (addr == NULL) {
		if (errno == EAUTH || errno == ENEEDAUTH)
			return ROBIN_PIGEON;
		return ROBIN_NOHOSTS;
	}

	/* just in case, this should never be possible after loops above */
	if (con->connect.hostindex >= con->connect.hosts.len
			|| con->connect.addrindex
			>= con->connect.hosts.val[con->connect.hostindex].addresses.len)
		fatalx("impossible index overflow just happened");

	bzero(&ss, sizeof(ss));
	if ((ret = robin_hostaddr2sockaddr(addr, (struct sockaddr *)&ss)))
		return ret;
	if ((fd = socket(ss.ss_family, SOCK_STREAM, 0)) == -1)
		return ROBIN_SYSTEM;

	bsize = ROBIN_SOCKBUF_SIZE;
	while (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bsize, sizeof(bsize)) == -1)
		bsize /= 2;
	bsize = ROBIN_SOCKBUF_SIZE;
	while (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bsize, sizeof(bsize)) == -1)
		bsize /= 2;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p connecting fd=%d host %s", con, fd,
				log_sockaddr((struct sockaddr *)&ss));

	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
		ret = ROBIN_SYSTEM;
		goto out;
	}
	if (connect(fd, (struct sockaddr *)&ss, ss.ss_len) == -1) {
		if (errno != EINPROGRESS && errno != EINTR)
			goto out;
	} else {
		/* fast as a roadrunner */
		connect_evcb(fd, EV_WRITE, con);
		return ROBIN_SUCCESS;
	}

	con->connect.state = CONNECT_ING;
	if (event_pending(&con->connect.timer, EV_WRITE|EV_TIMEOUT, NULL))
		event_del(&con->connect.timer);
	event_set(&con->connect.timer, fd, EV_WRITE, connect_evcb, con);
	event_add(&con->connect.timer, &tv);

	return ROBIN_SUCCESS;

out:
	if (fd != -1)
		close(fd);
	return ROBIN_SYSTEM;
}

/*
 * INTERNAL PROCESSORS
 */
static void
robin_do_accept(struct pigeon *p, void *arg)
{
	robin_con con = arg;
	int ret = ROBIN_SUCCESS;
	RobinHost *host;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p accept pigeon", con);

	/* safely skip over hostindex when socket connecting */
	if (con->connect.hosts.len == 0 && con->context->con.sfd != -1)
		goto out;

	/* processing without index host ... must be a server */
	if (con->connect.hostindex >= con->connect.hosts.len
			|| con->connect.addrindex
			>= con->connect.hosts.val[con->connect.hostindex].addresses.len) {
		log_warnx("robin_do_accept: hostindex out of bounds");
		ret = ROBIN_NOHOSTS;
		goto out;
	}

	if ((ret = robin_add_cellhostname(con->context,
					con->connect.hosts.val[con->connect.hostindex].hostname))) {
		log_warnx("adding accepting hostname to cell list");
		goto out;
	}
	if ((ret = robin_get_cellhost(con->context,
					con->connect.hosts.val[con->connect.hostindex].hostname,
					&host))) {
		log_warnx("getting accepting hostname from cell list");
		goto out;
	}
	if ((ret = robin_append_hostaddr(host,
					&con->connect.hosts.val[con->connect.hostindex].addresses
					.val[con->connect.addrindex]))) {
		log_warnx("appending working address to cell list");
		goto out;
	}

	con->host = &con->connect.hosts.val[con->connect.hostindex];

out:
	/* XXX: differential CELL/HOST/WREN how? */
	if (con->context->con.master == NULL)
		con->context->con.master = con;

	CALLBACK_INTERNAL(accept, con->context, con, ret);
}

/*
 * SERVER ACCEPT
 *
 * Do not set the internal cell pointers, etc.
 */
static void
robin_do_accept_server(struct pigeon *p, void *arg)
{
	robin_con con = arg;
	int ret = ROBIN_SUCCESS;

	CALLBACK_INTERNAL(accept, con->context, con, ret);
}

static void
robin_do_shutdown(struct pigeon *p, void *arg)
{
	robin_con con = arg;
	int ret = ROBIN_SUCCESS;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p shutdown pigeon", con);

	switch (errno) {
		case EAUTH:
		case ENEEDAUTH:
			ret = ROBIN_AUTH;
			con->connect.state = CONNECT_FAIL;
			break;
		case ECONNRESET:
			ret = ROBIN_DISCONNECTED;
			con->connect.state = CONNECT_TIMEDOUT;
			break;
		default:
			ret = ROBIN_SYSTEM;
			con->connect.state = CONNECT_FAIL;
			break;
	}

	/* this will be freed out from under us */
	con->p = NULL;

	CALLBACK_INTERNAL(shutdown, con->context, con, ret);

	/*
	 * do not free the connection handle, user may want to reuse it, but do
	 * not touch it, since the user may call robin_shutdown_con()
	 */
}

void
robin_connect_set_callbacks(robin_context context, robin_con con,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	con->cb.connect = connect;
	con->cb.accept = accept;
	con->cb.process = process;
	con->cb.shutdown = shutdown;
	con->cb.arg = arg;
}

/*
 * CONNECT to specified host.  Will call callback with the newly created
 * robin_con ready to go.
 *
 * Does not touch the CELL data in the context until the connection has
 * succeeded, at which point the host+addr pair that worked will be added.
 */
int
robin_connect_host(robin_context context, const RobinHost *host,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	int ret;
	robin_con con = NULL;
	RobinHost *rh = NULL;
	unsigned int u;

	if (context == NULL || host == NULL)
		return ROBIN_API_INVALID;

	/* host must have something in it - either hostname or addresses */
	if (host->addresses.len == 0 && host->hostname == NULL)
		return ROBIN_API_REQUIRED;

	/* allocate a private callback argument for event processing */
	if ((ret = robin_init_con(context, &con)))
		return ret;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p connect host", con);

	/* set the EXTERNAL PROCESSOR */
	robin_connect_set_callbacks(context, con, connect, accept, process,
			shutdown, arg);

	for (u = 0; u < con->connect.hosts.len; u++)
		if (strcmp(con->connect.hosts.val[u].hostname, host->hostname) == 0) {
			rh = &con->connect.hosts.val[u];
			break;
		}
	if (rh == NULL) {
		if ((rh = add_RobinHost(&con->connect.hosts)) == NULL)
			goto out;
		if ((ret = copy_RobinHost(host, rh)))
			goto out;
	}

	if (rh->addresses.len == 0) {
		if ((ret = lookup_dns(con, 0)))
			goto out;
	} else {
		if ((ret = socket_connect(con, 0, 0))) {
			log_debug("socket_connect failed in api: %s",
					robin_print_error(con->context, ret));
			goto out;
		}
	}

	return ROBIN_SUCCESS;

out:
	if (con)
		robin_free_con(context, con);
	return ret;
}

int
robin_connect_socket(robin_context context, int fd,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	int ret;
	robin_con con = NULL;

	if (context == NULL || fd == -1)
		return ROBIN_API_INVALID;

	/* allocate a private callback argument for event processing */
	if ((ret = robin_init_con(context, &con)))
		return ret;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p connect socket %d", con, fd);

	/* set the EXTERNAL PROCESSOR */
	robin_connect_set_callbacks(context, con, connect, accept, process,
			shutdown, arg);

	con->mode = PIGEON_MODE_CLIENT;
	connect_evcb(fd, EV_WRITE, con);
	return ROBIN_SUCCESS;
}

/*
 * Connect to the CELL.  Figure everything possible out.
 */
int
robin_connect(robin_context context,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	RobinHost host;
	robin_con con = NULL;
	char cellhost[MAXHOSTNAMELEN];
	unsigned int u;
	int ret;

	if (context == NULL)
		return ROBIN_API_INVALID;

	/* cell name is required, for now */
	if (context->cell.cellname == NULL)
		return ROBIN_API_REQUIRED;

	if (snprintf(cellhost, sizeof(cellhost), "_%s._tcp.%s",
				context->con.servname, context->cell.cellname) == -1)
		return ROBIN_SYSTEM;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CTX %p connect %p accept %p process %p shutdown %p "
				"arg %p",
				context, connect, accept, process, shutdown, arg);

	/*
	 * Try not to reconnect.  Having multiple connections to the cell is never
	 * a good idea.
	 */
	TAILQ_FOREACH(con, &context->con.list, entry)
		for (u = 0; u < con->connect.hosts.len; u++) {
			if (robin_verbose & ROBIN_LOG_CONNECT)
				log_debug("==] CON %p COMPARE connect %p accept %p process %p "
						"shutdown %p arg %p",
						con, con->cb.connect, con->cb.accept, con->cb.process,
						con->cb.shutdown, con->cb.arg);
			if (strcmp(con->connect.hosts.val[u].hostname, cellhost) == 0 &&
					con->cb.connect == connect && con->cb.accept == accept &&
					con->cb.process == process &&
					con->cb.shutdown == shutdown && con->cb.arg == arg) {
				log_info("==] CON %p re-requested host connect to %s state=%d",
						con, cellhost, con->connect.state);
				if (con->connect.state == CONNECT_ED) {
					accept(context, con, ROBIN_SUCCESS, arg);
					return ROBIN_SUCCESS;
				} else if (con->connect.state == CONNECT_FAIL ||
						con->connect.state == CONNECT_TIMEDOUT) {
					if ((ret = socket_connect(con, 0, 0)))
						log_debug("socket_connect failed in api: %s",
								robin_print_error(con->context, ret));
				}

				break;
			}
		}

	/*
	 * zero, and abuse the cellname.  This RobinHost will be copied by
	 * robin_connect_host(), so no worries about freeing the structure unless
	 * additional allocations are done in future.
	 */
	bzero(&host, sizeof(host));
	host.hostname = cellhost;

	return robin_connect_host(context, &host, connect, accept, process,
			shutdown, arg);
}

int
robin_server(robin_context context, int fd, robin_con *con,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	robin_con c = NULL;
	int ret;
	const char *principal;

	if (context == NULL)
		return ROBIN_API_INVALID;

	if ((ret = robin_init_con(context, &c)))
		return ret;

	c->connect.state = CONNECT_ED;
	c->mode = PIGEON_MODE_SERVER;
	robin_connect_set_callbacks(context, c, connect, accept, process,
			shutdown, arg);

	if (c->context->con.username && *c->context->con.username)
		principal = c->context->con.username;
	else
		principal = c->context->con.servname;

	if (c->cleartext)
		c->p = pigeon_breed_cleartext(fd,
				principal,
				c->mode,
				robin_do_accept_server,
				robin_api_connect_process,
				robin_do_shutdown,
				c);
	else
		c->p = pigeon_breed(fd,
				principal,
				c->mode,
				robin_do_accept_server,
				robin_api_connect_process,
				robin_do_shutdown,
				c);
	if (c->p == NULL) {
		log_warn("robin authenticating failed");
		robin_free_con(context, c);
		return ROBIN_PIGEON;
	}

	*con = c;

	return ROBIN_SUCCESS;
}
