/* $Gateweaver: robin.c,v 1.40 2007/05/22 03:03:48 cmaxwell Exp $ */
/*
 * Copyright (c) 2005 Christopher Maxwell.  All rights reserved.
 */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "robin_locl.h"
#include "pigeon.h"
#include <toolbox_asn1_der.h>
#include <toolbox_asn1_err.h>

#ifndef lint
RCSID("$Gateweaver: robin.c,v 1.40 2007/05/22 03:03:48 cmaxwell Exp $");
#endif

#ifdef ROBIN_LOGLEVEL
int robin_verbose = ROBIN_LOGLEVEL;
#else
int robin_verbose = 0;
#endif

/*
 * ROBIN PROCESSOR ARCHITECTURE
 * ============================
 *
 * 	1.	Data is received by callback from PIGEON by the INTERNAL processor.
 * 		Three messages are available: ACCEPT, PROCESS, SHUTDOWN.
 * 		[robin_connect.c]
 *
 * 	2.	Messages are sent to the ENGINE processor.  By default, this is the
 * 		STATE engine unless overridden by the user.  This allows filtering of
 * 		messages to match internal state, etc.
 * 		[robin_state.c]
 *
 * 	3.	Filtered messages are sent to the EXTERNAL processor.  This NOT
 * 		normally required for clients, as all client replies will trigger state
 * 		entries and callbacks before reaching this point.
 * 		[application]
 */

static char rfs_cell[MAXHOSTNAMELEN];
static tbkeyval rfs_conflist[] = {
	{ "cell",	rfs_cell,	sizeof(rfs_cell) },
	{ NULL,		NULL,		0 }
};

/*
 * Global initialization.  Basically just initialize event/dns.
 */
void
robin_init(void)
{
	extern void *current_base;
	static int once = 0;
	const char *filename;

	if (once)
		return;
	once = 1;

	/* some trickery to only init event once */
	if (current_base == NULL)
		event_init();
	dns_init();
	tbox_init();

	/* load some defaults */
	if ((filename = getenv(ROBIN_CONFENV)))
		tbloadconf(filename, rfs_conflist);
	else
		tbloadconf(ROBIN_CONFFILE, rfs_conflist);
}

const char *
robin_print_error(robin_context context, int code)
{
	const char *p = NULL;

	if (code == 0)
		return "success";
	if (context != NULL)
		p = tb_com_right(context->et_list, code);
	if (p == NULL)
		p = strerror(code);

	return p;
}

static void
robin_init_ets(robin_context context)
{
	if (context->et_list == NULL) {
		/* ROBIN error table */
		initialize_rbn_error_table_r(&context->et_list);

		/* ASN.1 error table */
		initialize_tasn_error_table_r(&context->et_list);

		/* TOOLBOX error table */
		initialize_tbox_error_table_r(&context->et_list);
	}
}

int
robin_init_context(robin_context *context)
{
	robin_context p;
	char hostname[MAXHOSTNAMELEN], *h;

	if (context == NULL)
		return EINVAL;

	if ((p = calloc(1, sizeof(*p))) == NULL)
		return ENOMEM;

	robin_init_ets(p);

	p->tv_cmdtimeout.tv_sec = ROBIN_CONNECT_TIMEOUT;
	p->tv_cmdtimeout.tv_usec = 0;

	/* init with default cell */
	if (strlen(rfs_cell) > 0) {
		p->cell.cellname = strdup(rfs_cell);
	} else {
		if (gethostname(hostname, sizeof(hostname)) == -1)
			return errno;
		for (h = hostname; *h; h++)
			*h = toupper(*h);
		if ((h = strchr(hostname, '.')))
			p->cell.cellname = strdup(++h);
		else
			p->cell.cellname = strdup(hostname);
	}
	if (p->cell.cellname == NULL) {
		tb_free_error_table(p->et_list);
		return ENOMEM;
	}

	TAILQ_INIT(&p->state);

	/* default ENGINE is STATE */
	p->cb.connect = (RCB_CONNECT *)robin_state_do_connect;
	p->cb.accept = (RCB_ACCEPT *)robin_state_do_accept;
	p->cb.process = (RCB_PROCESS *)robin_api_state_process;
	p->cb.shutdown = (RCB_SHUTDOWN *)robin_state_do_shutdown;
	p->cb.arg = NULL;

	/* default connection callbacks */
	p->defcb.connect = NULL;
	p->defcb.accept = NULL;
	p->defcb.process = NULL;
	p->defcb.shutdown = NULL;
	p->defcb.arg = NULL;

	TAILQ_INIT(&p->con.list);
	p->con.port = 1130;
	p->con.timeout = 30;				/* 30 seconds */
	p->con.username = strdup("");		/* should not be null */
	p->con.servname = strdup(ROBIN_SERVICE);
	p->con.connectas = PIGEON_MODE_USER;
	p->con.sfd = -1;

	ROBIN_ADD_CONTEXT(*context, p);

	return 0;
}

void
robin_free_context(robin_context context)
{
	struct robin_state *s, *s_n;
	robin_con con, con_n;

	/* manual decrement, this should be the last one */
	context->refcount--;
	if (context->refcount > 0) {
		log_debug("context has %u operations in progress", context->refcount);
		return;
	}

	/* abort all state entries still held */
	for (s = TAILQ_FIRST(&context->state);
			s != TAILQ_END(&context->state);
			s = s_n) {
		s_n = TAILQ_NEXT(s, entry);
		robin_state_abort(s, ROBIN_DISCONNECTED);
	}

	/* shutdown all the connections, before touching the context */
	for (con = TAILQ_FIRST(&context->con.list);
			con != TAILQ_END(&context->con.list);
			con = con_n) {
		con_n = TAILQ_NEXT(con, entry);
		robin_shutdown_con(context, con);
	}

	tb_free_error_table(context->et_list);

	/* free cell (containing hosts) after connections shut down */
	free_RobinCell(&context->cell);

	if (context->con.username)
		free(context->con.username);
	if (context->con.servname)
		free(context->con.servname);
	if (context->con.ccache)
		free(context->con.ccache);

	free(context);
}

/*
 * Manually shut down a context.  This allows the caller to force destruction
 * of all connections and state associated with the context.
 */
void
robin_shutdown_context(robin_context context)
{
	struct robin_state *s, *s_n;
	robin_context dummy = context;
	robin_con con, con_n;
	int last = 0;

	if (context->refcount == 1)
		last = 1;

	/* uncount the user's context handle, then abort states */
	ROBIN_DEL_CONTEXT(dummy, context);

	/* context was just freed */
	if (last)
		return;

	/* shutdown all the connections, before touching the context */
	for (con = TAILQ_FIRST(&context->con.list);
			con != TAILQ_END(&context->con.list);
			con = con_n) {
		con_n = TAILQ_NEXT(con, entry);
		robin_shutdown_con(context, con);
	}

	/* abort all state entries still held */
	for (s = TAILQ_FIRST(&context->state);
			s != TAILQ_END(&context->state);
			s = s_n) {
		s_n = TAILQ_NEXT(s, entry);
		robin_state_abort(s, ROBIN_DISCONNECTED);
	}
}

/*
 * Set the CELL name for the context.
 */
int
robin_set_cell(robin_context context, const char *cell)
{
	char *p = NULL;

	if (context == NULL)
		return ROBIN_API_INVALID;

	if (cell)
		if ((p = strdup(cell)) == NULL)
			return ROBIN_API_NOMEM;

	if (context->cell.cellname)
		free(context->cell.cellname);
	context->cell.cellname = p;

	return ROBIN_SUCCESS;
}

int
robin_set_service(robin_context context, const char *service)
{
	char *p = NULL;

	if (context == NULL)
		return ROBIN_API_INVALID;

	if (service)
		if ((p = strdup(service)) == NULL)
			return ROBIN_API_NOMEM;

	if (context->con.servname)
		free(context->con.servname);
	context->con.servname = p;

	return ROBIN_SUCCESS;
}

int
robin_set_port(robin_context context, int port)
{
	if (context == NULL)
		return ROBIN_API_INVALID;

	context->con.port = port;

	return ROBIN_SUCCESS;
}

int
robin_set_cleartext(robin_context context, int val)
{
	if (context == NULL)
		return ROBIN_API_INVALID;

	context->con.cleartext = val;

	return ROBIN_SUCCESS;
}

int
robin_set_con_cleartext(robin_context context, robin_con con,
		int noencrypt, int nosign)
{
	if (context == NULL || con == NULL || con->p == NULL)
		return ROBIN_API_INVALID;

	pigeon_set_cleartext(con->p, noencrypt, nosign);

	return ROBIN_SUCCESS;
}

int
robin_set_connect_socket(robin_context context, int fd)
{
	if (context == NULL)
		return ROBIN_API_INVALID;

	context->con.sfd = fd;

	return ROBIN_SUCCESS;
}

int
robin_set_ccache(robin_context context, const char *ccache)
{
	char *p = NULL;

	if (context == NULL)
		return ROBIN_API_INVALID;

	if (ccache)
		if ((p = strdup(ccache)) == NULL)
			return ROBIN_API_NOMEM;

	if (context->con.ccache)
		free(context->con.ccache);
	context->con.ccache = p;

	return ROBIN_SUCCESS;
}

/*
 * Initialize a connection handle.  Default to a USER connection, as the apps
 * using SERVER and CLIENT should better well know what they are doing!
 */
int
robin_init_con(robin_context context, robin_con *con)
{
	robin_con p;

	if (context == NULL || con == NULL)
		return ROBIN_API_INVALID;

	if ((p = calloc(1, sizeof(*p))) == NULL)
		return ROBIN_API_NOMEM;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p init", p);
	
	p->mode = context->con.connectas;
	p->cleartext = context->con.cleartext;
#ifdef ROBIN_RANDOM_XID
	p->xid = arc4random();
#else
	p->xid = 1;
#endif
	ROBIN_ADD_CONTEXT(p->context, context);

	TAILQ_INSERT_TAIL(&context->con.list, p, entry);

	*con = p;

	return ROBIN_SUCCESS;
}

/*
 * Free the robin_con structure.  This does NOT free/shutdown the pigeon
 * control structure.  robin_do_shutdown() should be used to safely shutdown
 * and free without looping.
 *
 * XXX USERS SHOULD NEVER CALL THIS FUNCTION DIRECTLY XXX
 */
void
robin_free_con(robin_context context, robin_con con)
{
	robin_con p;
	struct robin_state *s, *s_n;

	/* Make sure the con is in this context's list */
	TAILQ_FOREACH(p, &context->con.list, entry)
		if (p == con)
			break;
	if (p == TAILQ_END(&context->con.list))
		return;

	/* set a destruction pointer to prevent looping */
	if (con->destroying)
		return;
	else
		con->destroying = 1;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p free", con);

	/* take out of the connection list early */
	TAILQ_REMOVE(&context->con.list, con, entry);

	/* unset the 'master' connection */
	if (con->context->con.master == con)
		con->context->con.master = NULL;

	/* abort STATE_CONN entries that match this connection */
	for (s = TAILQ_FIRST(&context->state);
			s != TAILQ_END(&context->state);
			s = s_n) {
		s_n = TAILQ_NEXT(s, entry);
		if (s->con == con) {
			/* unreference the connection always */
			s->con = NULL;
			/* remove the state sometimes */
			if ((s->state & STATE_CONN))
				robin_state_abort(s, ROBIN_DISCONNECTED);
			else
				robin_state_resend(s);
		}
	}
	dns_abort_byarg(con);

	ROBIN_DEL_CONTEXT(con->context, context);
	free_RobinHosts(&con->connect.hosts);
	evtimer_del(&con->connect.timer);

	free(con);
}

/*
 * Safe method of determining whether a connection is still associated with
 * a context connection list.
 */
int
robin_valid_con(robin_context context, robin_con con)
{
	robin_con rc;
	TAILQ_FOREACH(rc, &context->con.list, entry)
		if (rc == con)
			return ROBIN_SUCCESS;
	return ROBIN_NOTFOUND;
}

/*
 * Robin connection shutdown.  This is user-safe, and calls the internal robin
 * callbacks for the pigeon connection, which will internally call
 * robin_free_con().  If the pigeon has already been freed, or was never init'd
 */
void
robin_shutdown_con(robin_context context, robin_con con)
{
	robin_con p;

	if (robin_verbose & ROBIN_LOG_CONNECT)
		log_debug("==] CON %p shutdown", con);

	/* Make sure the con is in this context's list */
	TAILQ_FOREACH(p, &context->con.list, entry)
		if (p == con)
			break;
	if (p == TAILQ_END(&context->con.list))
		return;

	if (con->p)
		pigeon_shutdown(&con->p);
	else
		robin_free_con(context, con);
}

/*
 * Set the pigeon connection for use by the con robin handlers.  This does not
 * close down the original.
 */
int
robin_con_setpigeon(robin_context context, robin_con con, struct pigeon *p)
{
	if (context == NULL || con == NULL)
		return ROBIN_API_INVALID;

	con->p = p;

	return ROBIN_SUCCESS;
}

int
robin_con_getpigeon(robin_context context, robin_con con, struct pigeon **p)
{
	if (context == NULL || con == NULL || p == NULL)
		return ROBIN_API_INVALID;

	*p = con->p;

	return ROBIN_SUCCESS;
}

/*
 * Set up the message header.  Transaction ID is per-connection.  No user is
 * set, use robin_header_proxy() instead.
 */
void
robin_header(robin_context context, robin_con con, RobinHeader *hdr)
{
	hdr->pvno = ROBIN_PROT_VER;
	hdr->xid = ++con->xid;
}

/*
 * Set the context-wide engine to process messages with.  Default is to use the
 * STATE engine.  ENGINES should call the private connection processors when
 * appropriate.
 */
void
robin_set_engine(robin_context context,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	context->cb.connect = connect;
	context->cb.accept = accept;
	context->cb.process = process;
	context->cb.shutdown = shutdown;
	context->cb.arg = arg;
}

void
robin_set_default_callbacks(robin_context context,
		RCB_CONNECT *connect, RCB_ACCEPT *accept, RCB_PROCESS *process,
		RCB_SHUTDOWN *shutdown, void *arg)
{
	context->defcb.connect = connect;
	context->defcb.accept = accept;
	context->defcb.process = process;
	context->defcb.shutdown = shutdown;
	context->defcb.arg = arg;
}

void
robin_set_connectas_client(robin_context context)
{
	context->con.connectas = PIGEON_MODE_CLIENT;
}

int
robin_set_username(robin_context context, const char *username)
{
	char *p = NULL;

	if (context == NULL)
		return ROBIN_API_INVALID;

	if (username)
		if ((p = strdup(username)) == NULL)
			return ROBIN_API_NOMEM;

	if (context->con.username)
		free(context->con.username);
	context->con.username = p;

	return ROBIN_SUCCESS;
}

int
robin_set_con_timeout(robin_context context, robin_con con, time_t timeout)
{
	if (context == NULL || con == NULL || con->p == NULL)
		return ROBIN_API_INVALID;

	pigeon_set_timeout(con->p, timeout);

	return ROBIN_SUCCESS;
}
