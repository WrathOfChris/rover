/* $Gateweaver: pigeon.c,v 1.37 2007/03/23 16:17:14 cmaxwell Exp $ */
/*
 * Copyright (c) 2005 Christopher Maxwell.  All rights reserved.
 */
#include <sys/time.h>
#include <errno.h>
#include <event.h>
#include <gssapi.h>
#include <stdlib.h>
#include <string.h>
#include "pigeon_locl.h"

#ifndef lint
RCSID("$Gateweaver: pigeon.c,v 1.37 2007/03/23 16:17:14 cmaxwell Exp $");
#endif

static int __pigeon_verbose = 0;

static void pigeon_read(struct bufferevent *, void *);
static void pigeon_write_cb(struct bufferevent *, void *);
static void pigeon_error(struct bufferevent *, short, void *);

static struct gss_context * pigeon_gss_new(void);
static void pigeon_gss_destroy(struct gss_context **);
static void pigeon_gss_log_err(struct gss_context *, char *);
static struct gss_context * pigeon_gss_init_context(enum pigeon_mode,
		const char *);

/*
 * Create a new pigeon object, with callbacks for post-layer actions
 */
struct pigeon *
pigeon_breed(int fd, const char *service, enum pigeon_mode mode,
		void (*accept_cb)(struct pigeon *, void *),
		void (*process_cb)(struct pigeon *, gss_buffer_desc *, void *),
		void (*shutdown_cb)(struct pigeon *, void *),
		void *arg)
{
	struct pigeon *p;

	if (fd == -1 || !service) {
		errno = EINVAL;
		return NULL;
	}

	if ((p = calloc(1, sizeof(struct pigeon))) == NULL)
		return NULL;

	if ((p->bev = bufferevent_new(fd, pigeon_read, pigeon_write_cb,
					pigeon_error, p)) == NULL) {
		if (__pigeon_verbose > 0)
			log_warn("pigeon breeding new bufferevent");
		free(p);
		return NULL;
	}

	p->accept = accept_cb;
	p->process = process_cb;
	p->shutdown = shutdown_cb;
	p->arg = arg;

	if (PIGEON_ENCRYPT == 0)
		p->noencrypt = 1;
	if (PIGEON_SIGN == 0)
		p->nosign = 1;

	if ((p->ctx = pigeon_gss_init_context(mode, service)) == NULL) {
		if (__pigeon_verbose > 0)
			log_warn("pigeon breeding new gssapi context");
		bufferevent_free(p->bev);
		free(p);
		return NULL;
	}

	bufferevent_settimeout(p->bev, PIGEON_TIMEOUT, PIGEON_TIMEOUT);
	bufferevent_enable(p->bev, EV_READ);

	return p;
}

struct pigeon *
pigeon_breed_cleartext(int fd, const char *service, enum pigeon_mode mode,
		void (*accept_cb)(struct pigeon *, void *),
		void (*process_cb)(struct pigeon *, gss_buffer_desc *, void *),
		void (*shutdown_cb)(struct pigeon *, void *),
		void *arg)
{
	struct pigeon *p;

	if (fd == -1 || !service) {
		errno = EINVAL;
		return NULL;
	}

	if ((p = calloc(1, sizeof(struct pigeon))) == NULL)
		return NULL;

	if ((p->bev = bufferevent_new(fd, pigeon_read, pigeon_write_cb,
					pigeon_error, p)) == NULL) {
		if (__pigeon_verbose > 0)
			log_warn("pigeon breeding new bufferevent");
		free(p);
		return NULL;
	}

	p->accept = accept_cb;
	p->process = process_cb;
	p->shutdown = shutdown_cb;
	p->arg = arg;

	p->noencrypt = 1;
	p->nosign = 1;

	if ((p->ctx = pigeon_gss_init_context(mode, service)) == NULL) {
		if (__pigeon_verbose > 0)
			log_warn("pigeon breeding new gssapi context");
		bufferevent_free(p->bev);
		free(p);
		return NULL;
	}

	bufferevent_settimeout(p->bev, PIGEON_TIMEOUT, PIGEON_TIMEOUT);
	bufferevent_enable(p->bev, EV_READ);

	return p;
}

/*
 * internal token write function
 */
static ssize_t
pigeon_write_token(struct bufferevent *bev, gss_buffer_desc *tok)
{
	int n;
	size_t tlen;

	if (!bev || !tok || !tok->value) {
		errno = EINVAL;
		return -1;
	}

	tlen = htonl(tok->length);
	if (bufferevent_write(bev, (char *)&tlen, sizeof(tlen)) == -1)
		return -1;
	if ((n = bufferevent_write(bev, tok->value, tok->length)) == -1)
		return -1;

	return n + sizeof(tlen);
}

/*
 * external write function
 */
int
pigeon_write(struct pigeon *pigeon, char *buf, size_t len)
{
	gss_buffer_desc tok, out_buf;
	OM_uint32 junk;
	int state, n, encflag = 1;

	if (!pigeon || !pigeon->ctx || !pigeon->bev || !buf) {
		errno = EINVAL;
		return -1;
	}

	if (pigeon->noencrypt && pigeon->nosign) {
		out_buf.value = buf;
		out_buf.length = len;
		n = pigeon_write_token(pigeon->bev, &out_buf);
	} else {
		tok.value = buf;
		tok.length = len;

		if (pigeon->noencrypt)
			encflag = 0;

		pigeon->ctx->major = gss_wrap(&pigeon->ctx->minor,
				pigeon->ctx->context,
				encflag,
				GSS_C_QOP_DEFAULT,
				&tok,
				&state,
				&out_buf);
		if (GSS_ERROR(pigeon->ctx->major)) {
			pigeon_gss_log_err(pigeon->ctx, "pigeon_write");
			errno = EAUTH;
			return -1;
		}

		if (!state && !pigeon->noencrypt) {
			gss_release_buffer(&junk, &out_buf);
			if (__pigeon_verbose > 0)
				log_warnx("could not encrypt data");
			return -1;
		}

		n = pigeon_write_token(pigeon->bev, &out_buf);
		gss_release_buffer(&junk, &out_buf);
	}

	if (__pigeon_verbose > 2)
		log_debug("[PWRITE][%d] %zu bytes", pigeon->bev->ev_read.ev_fd, len);

	return n;
}

/*
 * Handle accepting the security context, advancing state to AUTHENTICATED
 * when completed.
 */
static int
pigeon_accept(struct pigeon *pigeon, gss_buffer_desc *tok)
{
	gss_buffer_desc out_tok;
	OM_uint32 ret_flags, junk;

	if (!pigeon || !pigeon->ctx) {
		errno = EINVAL;
		return -1;
	}

	pigeon->ctx->major = gss_accept_sec_context(&pigeon->ctx->minor,
			&pigeon->ctx->context,
			pigeon->ctx->server_creds,
			tok,
			GSS_C_NO_CHANNEL_BINDINGS,
			&pigeon->ctx->client_name,
			&pigeon->ctx->oid,
			&out_tok,
			&ret_flags,
			NULL,	/* ignore time_rec */
			NULL);	/* ignore del_cred_handle */

	if (out_tok.length != 0) {
		if (pigeon_write_token(pigeon->bev, &out_tok) == -1) {
			gss_release_buffer(&junk, &out_tok);
			return -1;
		}
		gss_release_buffer(&junk, &out_tok);
	}

	if (GSS_ERROR(pigeon->ctx->major)) {
		pigeon_gss_log_err(pigeon->ctx, "gss_accept_sec_context");
		/* do not shutdown on error, that's why we return -1 */
		errno = ECONNABORTED;
		return -1;
	}

	if (pigeon->ctx->major != GSS_S_CONTINUE_NEEDED) {
		pigeon->ctx->state = GSS_STATE_AUTHENTICATED;

		if (pigeon->accept)
			pigeon->accept(pigeon, pigeon->arg);
		if (pigeon->killme)
			return -1;
	}

	return 0;
}

/*
 * first time, this gets called with
 * 	tok = GSS_C_NO_BUFFER
 * caller is responsible for freeing (tok)
 */
static int
pigeon_fly(struct pigeon *pigeon, gss_buffer_desc *tok)
{
	int deleg_flag = 0;
	uint32_t ret_flags;
	gss_buffer_desc send_tok;
	OM_uint32 junk;

	if (!pigeon || !pigeon->ctx || !pigeon->bev) {
		errno = EINVAL;
		return -1;
	}

	pigeon->ctx->state = GSS_STATE_AUTHCON;

	/*
	 * reset credential cache to user supplied ccache.  If ccache_name is NULL,
	 * it will be reset to defaults (which keeps cross-contamination down
	 */
	pigeon->ctx->major = gss_krb5_ccache_name(&pigeon->ctx->minor,
			pigeon->ctx->ccache_name,
			NULL);
	/* error is nonfatal, but report it */
	if (GSS_ERROR(pigeon->ctx->major))
		pigeon_gss_log_err(pigeon->ctx, "gss_krb5_ccache_name");

	pigeon->ctx->major = gss_init_sec_context(&pigeon->ctx->minor,
			pigeon->ctx->client_creds,
			&pigeon->ctx->context,
			pigeon->ctx->server_name,
			pigeon->ctx->oid,
			GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
				GSS_C_SEQUENCE_FLAG | deleg_flag,
			0,
			NULL,	/* no channel bindings */
			tok,
			NULL,	/* ignore mech type */
			&send_tok,
			&ret_flags,
			NULL);	/* ignore time_rec */

	if (!(ret_flags & GSS_C_MUTUAL_FLAG)) {
		if (__pigeon_verbose > 0)
			log_warnx("ALARM!  MUTUAL AUTH NOT DONE F:%u", ret_flags);
		if (GSS_ERROR(pigeon->ctx->major))
			pigeon_gss_log_err(pigeon->ctx, "gss_init_sec_context");
		errno = ENEEDAUTH;
		return -1;
	}

	if (send_tok.length != 0) {
		if (pigeon_write_token(pigeon->bev, &send_tok) == -1) {
			gss_release_buffer(&junk, &send_tok);
			return -1;
		}
		gss_release_buffer(&junk, &send_tok);
	}

	/* do not call shutdown here ... thats what the -1 is for */
	if (GSS_ERROR(pigeon->ctx->major)) {
		pigeon_gss_log_err(pigeon->ctx, "gss_init_sec_context");
		errno = ECONNABORTED;
		return -1;
	}

	if (pigeon->ctx->major != GSS_S_CONTINUE_NEEDED) {
		pigeon->ctx->state = GSS_STATE_AUTHENTICATED;

		pigeon->ctx->major = gss_inquire_context(&pigeon->ctx->minor,
				pigeon->ctx->context,
				NULL,	/* src */
				&pigeon->ctx->server_name,
				NULL,	/* lifetime */
				NULL,	/* mechanism */
				NULL,	/* context_flags */
				NULL,	/* is_local */
				NULL);	/* is_open */
		if (GSS_ERROR(pigeon->ctx->major))
			pigeon_gss_log_err(pigeon->ctx, "gss_inquire_context");

		if (pigeon->accept)
			pigeon->accept(pigeon, pigeon->arg);
		if (pigeon->killme)
			return -1;
	}

	return 0;
}

int
pigeon_connect(struct pigeon *pigeon, const char *service)
{
	gss_buffer_desc namebuf;

	if (!pigeon || !pigeon->ctx || !service) {
		errno = EINVAL;
		return -1;
	}

	namebuf.value = (char *)service;
	namebuf.length = strlen(namebuf.value) + 1;

	pigeon->ctx->major = gss_import_name(&pigeon->ctx->minor,
			&namebuf,
			GSS_C_NT_HOSTBASED_SERVICE,
			&pigeon->ctx->server_name);

	return pigeon_fly(pigeon, GSS_C_NO_BUFFER);
}

/*
 * process (unencrypt) packet
 */
static int
pigeon_process(struct pigeon *pigeon, gss_buffer_desc *tok)
{
	gss_buffer_desc out_tok;
	int state;
	OM_uint32 junk;

	if (!pigeon || !pigeon->ctx || !tok) {
		errno = EINVAL;
		return -1;
	}

	if (pigeon->noencrypt && pigeon->nosign) {
		if (pigeon->process)
			pigeon->process(pigeon, tok, pigeon->arg);
	} else {
		pigeon->ctx->major = gss_unwrap(&pigeon->ctx->minor,
				pigeon->ctx->context,
				tok,
				&out_tok,
				&state,
				NULL);
		if (GSS_ERROR(pigeon->ctx->major))
			pigeon_gss_log_err(pigeon->ctx, "gss_unwrap");

		if (!state && !pigeon->noencrypt) {
			gss_release_buffer(&junk, &out_tok);
			if (__pigeon_verbose > 0)
				log_warnx("data required encryption, but none present");
			return -1;
		}

		if (pigeon->process)
			pigeon->process(pigeon, &out_tok, pigeon->arg);

		gss_release_buffer(&junk, &out_tok);
	}

	/* was pigeon_set_shutdown() by process handler */
	if (pigeon->killme)
		return -1;

	return 0;
}

/*
 * bufferevent calls this, we then call out to accept() or process()
 */
static void
pigeon_read(struct bufferevent *bev, void *arg)
{
	struct pigeon *pigeon = arg;
	struct evbuffer *evb;
	unsigned char *p;
	size_t dlen = 0;
	gss_buffer_desc tok;

	evb = EVBUFFER_INPUT(bev);

	if (__pigeon_verbose > 2)
		log_debug("[GSSREAD][%d] %zu bytes", bev->ev_read.ev_fd,
				EVBUFFER_LENGTH(evb));
	if (__pigeon_verbose > 3)
		log_hexdump(EVBUFFER_DATA(evb), EVBUFFER_LENGTH(evb));

	/* reset (p) with every loop.  Buffer address may have changed */
	while ((p = EVBUFFER_DATA(evb) + dlen) < (EVBUFFER_DATA(evb) +
				EVBUFFER_LENGTH(evb))) {
		size_t plen, tmpp;

		/* make sure to check for enough data before EVERY iteration */
		if ((p + sizeof(size_t))
				> (EVBUFFER_DATA(evb) + EVBUFFER_LENGTH(evb)))
			break;

		memcpy(&tmpp, p, sizeof(size_t));

		plen = ntohl(tmpp);
		p += sizeof(size_t);

		if ((p + plen) > (EVBUFFER_DATA(evb) + EVBUFFER_LENGTH(evb))) {
			if (__pigeon_verbose > 2)
				log_debug("[GSSREAD] truncated packet: want %zu more, "
						"have %zu, waiting", plen, EVBUFFER_LENGTH(evb));
			break;
		}

		if (__pigeon_verbose > 2)
			log_debug("[GSSPROC][%d] %zu bytes.  buf 0x%p ptr 0x%p max 0x%p",
					bev->ev_read.ev_fd, plen,
					EVBUFFER_DATA(evb), p,
					EVBUFFER_DATA(evb) + EVBUFFER_LENGTH(evb));

		tok.length = plen;
		tok.value = p;

		/* gss token buffer is ready */

		switch (pigeon->ctx->state) {
			case GSS_STATE_NONE:
				pigeon_shutdown(&pigeon);
				errno = EOPNOTSUPP;
				return;
			case GSS_STATE_AUTHCON:
				if (pigeon_fly(pigeon, &tok) == -1) {
					pigeon_shutdown(&pigeon);
					return;
				}
				break;

			case GSS_STATE_AUTHNEG:
				if (pigeon_accept(pigeon, &tok) == -1) {
					pigeon_shutdown(&pigeon);
					return;
				}
				break;

			case GSS_STATE_AUTHENTICATED:
				if (pigeon_process(pigeon, &tok) == -1) {
					pigeon_shutdown(&pigeon);
					return;
				}
				break;
		}

		/* cleanup */
		dlen += plen + sizeof(size_t);
	}

	evbuffer_drain(evb, dlen);
}

static void
pigeon_write_cb(struct bufferevent *bev, void *arg)
{
}

static void
pigeon_error(struct bufferevent *bev, short which, void *arg)
{
	struct pigeon *pigeon = arg;

	if (which & EVBUFFER_TIMEOUT) {
		errno = ETIMEDOUT;
		if (__pigeon_verbose > 0)
			log_debug("pigeon timed out");
	}

	if (which & EVBUFFER_ERROR)
		if (__pigeon_verbose > 0)
			log_warn("pigeon error");

	if (which & EVBUFFER_EOF) {
		errno = ECONNRESET;
		if (__pigeon_verbose > 0)
			log_debug("pigeon closed");
	}

	pigeon_shutdown(&pigeon);
}

void
pigeon_set_shutdown(struct pigeon *pigeon)
{
	if (pigeon == NULL)
		return;
	pigeon->killme = 1;
}

void
pigeon_shutdown(struct pigeon **pigeon)
{
	struct pigeon *p;

	if (pigeon == NULL || *pigeon == NULL)
		return;
	if ((*pigeon)->shutdown_counter++ > 0)
		fatalx("pigeon_shutdown re-entry!!!");

	/* save a local copy before calling user shutdown */
	p = *pigeon;

	pigeon_gss_destroy(&p->ctx);

	if (p->shutdown)
		p->shutdown(p, p->arg);

	if (shutdown(p->bev->ev_read.ev_fd, SHUT_RDWR) == -1)
		if (__pigeon_verbose > 0)
			log_warn("pigeon shutdown");
	if (close(p->bev->ev_read.ev_fd) == -1)
		if (__pigeon_verbose > 0)
			log_warn("pigeon close");

	if (p->bev->ev_read.ev_fd != p->bev->ev_write.ev_fd) {
		if (shutdown(p->bev->ev_write.ev_fd, SHUT_RDWR) == -1)
			if (__pigeon_verbose > 0)
				log_warn("pigeon shutdown");
		if (close(p->bev->ev_write.ev_fd) == -1)
			if (__pigeon_verbose > 0)
				log_warn("pigeon close");
	}

	bufferevent_free(p->bev);
	free(p);
	if (*pigeon)
		*pigeon = NULL;
}

static char *
pigeon_print_name(struct pigeon *pigeon, gss_name_t gssname)
{
	static char name[PIGEON_NAMELEN];
	gss_buffer_desc client_name;
	size_t n;
	OM_uint32 junk;

	if (!pigeon || !gssname || !pigeon->ctx) {
		errno = EINVAL;
		return NULL;
	}

	pigeon->ctx->major = gss_display_name(&pigeon->ctx->minor,
			gssname,
			&client_name,
			NULL);
	if (GSS_ERROR(pigeon->ctx->major))
		pigeon_gss_log_err(pigeon->ctx, "gss_display_name(client)");

	if (client_name.length < sizeof(name) - 1)
		n = client_name.length;
	else
		n = sizeof(name) - 1;

	memcpy(name, client_name.value, n);
	name[n] = '\0';
	gss_release_buffer(&junk, &client_name);

	return name;
}

char *
pigeon_print_clientname(struct pigeon *pigeon)
{
	if (!pigeon || !pigeon->ctx)
		return "(unknown)";
	return pigeon_print_name(pigeon, pigeon->ctx->client_name);
}

char *
pigeon_print_servername(struct pigeon *pigeon)
{
	if (!pigeon || !pigeon->ctx)
		return "(unknown)";
	return pigeon_print_name(pigeon, pigeon->ctx->server_name);
}

#if 0
/*
 * XXX not supposed to use gss_display_name() for access control.
 * gss_export_name() creates a binary blob to compare, but that's a PITA
 * for now.
 */
char *
pigeon_print_canon(struct pigeon *pigeon, gss_name_t gssname)
{
	static char name[PIGEON_NAMELEN];
	gss_buffer_desc export_name;
	size_t n;
	OM_uint32 junk;

	pigeon->ctx->major = gss_export_name(&pigeon->ctx->minor,
			gssname,
			&export_name);
	if (GSS_ERROR(pigeon->ctx->major))
		pigeon_gss_log_err(pigeon->ctx, "gss_export_name");

	if (export_name.length < sizeof(name) - 1)
		n = export_name.length;
	else
		n = sizeof(name) - 1;

	memcpy(name, export_name.value, n);
	name[n] = '\0';
	gss_release_buffer(&junk, &export_name);

	return name;
}
#endif

/*
 * GSSAPI functions
 */
static struct gss_context *
pigeon_gss_new(void)
{
	struct gss_context *ctx;

	if ((ctx = calloc(1, sizeof(struct gss_context))) == NULL)
		return NULL;

	ctx->context = GSS_C_NO_CONTEXT;
	ctx->oid = GSS_C_NO_OID;
	ctx->client_name = GSS_C_NO_NAME;
	ctx->server_name = GSS_C_NO_NAME;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	ctx->server_creds = GSS_C_NO_CREDENTIAL;

	return ctx;
}

static void
pigeon_gss_destroy(struct gss_context **ctx)
{
	OM_uint32 ms;

	if (ctx == NULL || *ctx == NULL)
		return;

	if ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
#if 0
	if ((*ctx)->oid != GSS_C_NO_OID) {
		free((*ctx)->oid->elements);
		free((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
#endif
	if ((*ctx)->client_name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client_name);
	if ((*ctx)->server_name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->server_name);
	if ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);
	if ((*ctx)->server_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->server_creds);
	if ((*ctx)->ccache_name)
		free((*ctx)->ccache_name);
	free(*ctx);
	*ctx = NULL;
}

static void
pigeon_gss_log_errcode(char *m, OM_uint32 code, int type)
{
	OM_uint32 maj, min, msg_ctx;
	gss_buffer_desc msg;

	msg_ctx = 0;
	for (;;) {
		maj = gss_display_status(&min,
				code,
				type,
				GSS_C_NO_OID,
				&msg_ctx,
				&msg);
		if (__pigeon_verbose > 0)
			log_warnx("GSSAPI %s: %s", m, (char *)msg.value);
		gss_release_buffer(&min, &msg);
		if (!msg_ctx)
			break;
	}
}

static void
pigeon_gss_log_err(struct gss_context *ctx, char *msg)
{
	pigeon_gss_log_errcode(msg, ctx->major, GSS_C_GSS_CODE);
	if (GSS_ERROR(ctx->minor))
		pigeon_gss_log_errcode(msg, ctx->minor, GSS_C_MECH_CODE);
}

static struct gss_context *
pigeon_gss_init_context(enum pigeon_mode mode, const char *name)
{
	struct gss_context *ctx;
	gss_buffer_desc namebuf;
	gss_name_t nameptr = NULL;
	gss_cred_id_t *credptr = NULL;
	gss_cred_usage_t credtype = 0;

	if ((ctx = pigeon_gss_new()) == NULL)
		fatal("gss_init_server");

	namebuf.value = (char *)name;
	namebuf.length = strlen(namebuf.value) + 1;

	switch (mode) {
		case PIGEON_MODE_SERVER:
			ctx->major = gss_import_name(&ctx->minor,
					&namebuf,
					GSS_C_NT_HOSTBASED_SERVICE,
					&ctx->server_name);
			nameptr = ctx->server_name;
			credptr = &ctx->server_creds;
			credtype = GSS_C_ACCEPT;
			ctx->state = GSS_STATE_AUTHNEG;
			break;

		case PIGEON_MODE_CLIENT:
			ctx->major = gss_import_name(&ctx->minor,
					&namebuf,
					GSS_C_NT_HOSTBASED_SERVICE,
					&ctx->client_name);
			nameptr = ctx->client_name;
			credptr = &ctx->client_creds;
			credtype = GSS_C_INITIATE;
			ctx->state = GSS_STATE_AUTHCON;
			break;

		case PIGEON_MODE_USER:
			//if (namebuf.value && namebuf.length > 1) {
			if (namebuf.value) {
				ctx->major = gss_import_name(&ctx->minor,
						&namebuf,
						GSS_C_NT_USER_NAME,
						&ctx->client_name);
				nameptr = ctx->client_name;
				credptr = &ctx->client_creds;
			} else {
				nameptr = GSS_C_NO_NAME;
				credptr = NULL;
			}
			credtype = GSS_C_INITIATE;
			ctx->state = GSS_STATE_AUTHCON;
			break;

		case PIGEON_MODE_BOTH:
			if (__pigeon_verbose > 0)
				log_debug("PIGEON_MODE_BOTH not supported");
			return NULL;
	}
	if (GSS_ERROR(ctx->major))
		pigeon_gss_log_err(ctx, "gss_import_name");

	/* user mode does not acquire creds from the keytab */
	if (mode == PIGEON_MODE_USER)
		return ctx;

	ctx->major = gss_acquire_cred(&ctx->minor,
			nameptr,
			0,
			GSS_C_NULL_OID_SET,
			credtype,
			credptr,
			NULL,
			NULL);
	if (GSS_ERROR(ctx->major))
		pigeon_gss_log_err(ctx, "gss_acquire_cred");

	return ctx;
}

#if 0
static char *
pigeon_gss_flags_print(OM_uint32 flags)
{
	static char flagtext[256];

	strlcpy(flagtext, "", sizeof(flagtext));
	if (flags & GSS_C_DELEG_FLAG)
		strlcat(flagtext, "D", sizeof(flagtext));
	if (flags & GSS_C_MUTUAL_FLAG)
		strlcat(flagtext, "M", sizeof(flagtext));
	if (flags & GSS_C_REPLAY_FLAG)
		strlcat(flagtext, "R", sizeof(flagtext));
	if (flags & GSS_C_SEQUENCE_FLAG)
		strlcat(flagtext, "S", sizeof(flagtext));
	if (flags & GSS_C_CONF_FLAG)
		strlcat(flagtext, "C", sizeof(flagtext));
	if (flags & GSS_C_INTEG_FLAG)
		strlcat(flagtext, "I", sizeof(flagtext));

	return flagtext;
}

/*
 * simple/sync returns to exit the event_dispatch() loops in _s() functions
 */
void
pigeon_accept_s(struct pigeon *cp, void *arg)
{
	errno = 0;
	event_loopexit(NULL);
}

void
pigeon_shutdown_s(struct pigeon *cp, void *arg)
{
	event_loopexit(NULL);
}

/*
 * Simple process manager that simply exits the event loop when status messages
 * are received.
 */
void
pigeon_process_s(struct pigeon *cp, gss_buffer_desc *tok, void *arg)
{
	unsigned char *ptr, *p;
	size_t len;
	int status;

	len = tok->length;
	ptr = tok->value;

	if (len < sizeof(struct scroll_header)) {
		errno = ERANGE;
		event_loopexit(NULL);
		return;
	}

	p = ptr;
	while (p < (ptr + len)) {
		struct scroll_header *hdr;
		size_t plen;

		hdr = (struct scroll_header *)p;
		plen = ntohs(hdr->len);

		if (plen < sizeof(struct scroll_header)) {
			errno = ERANGE;
			event_loopexit(NULL);
			return;
		}

		if ((p + plen) > (ptr + len)) {
			errno = EMSGSIZE;
			event_loopexit(NULL);
			return;
		}

		switch (hdr->type) {
			case SCROLL_PING:
				if (scroll_pong(cp) == -1) {
					event_loopexit(NULL);
					return;
				}
				break;
			case SCROLL_STATUS:
				status = ntohl(((struct scroll_status *)p)->status);
				if (status != SS_OK)
					errno = scroll_ss2errno(status);
				else
					errno = 0;
				event_loopexit(NULL);
				break;
			default:
				errno = EOPNOTSUPP;
				event_loopexit(NULL);
				return;
		}
		p += plen;
	}
}

struct pigeon *
pigeon_connect_s(int fd, const char *service, enum pigeon_mode mode,
		void (*cb)(struct pigeon *, gss_buffer_desc *, void *))
{
	struct pigeon *p;

	if (fd == -1 || !service) {
		errno = EINVAL;
		return NULL;
	}

	if ((p = pigeon_breed(fd, service, mode,
					pigeon_accept_s,
					cb,
					pigeon_shutdown_s,
					NULL)) == NULL)
		return NULL;

	if (pigeon_connect(p, service) == -1) {
		/* pigeon_shutdown() without closing socket */
		pigeon_gss_destroy(&p->ctx);
		bufferevent_free(p->bev);
		free(p);
		return NULL;
	}

	/* allow event processing until accept_s() is called */
	event_dispatch();

	return p;
}

int
pigeon_wait(void)
{
	int ret;

	ret = event_dispatch();

	/*
	 * 0:	terminated by request
	 * 1:	terminated by no events
	 * -1:	terminated by error
	 */
	if (ret == 0 || ret == -1)
		if (errno != 0)
			return -1;
	return 0;
}
#endif

int
pigeon_isconnected(struct pigeon *cp)
{
	if (!cp || !cp->ctx)
		return 0;

	switch (cp->ctx->state) {
		case GSS_STATE_NONE:
		case GSS_STATE_AUTHCON:
		case GSS_STATE_AUTHNEG:
			break;
		case GSS_STATE_AUTHENTICATED:
			return 1;
	}

	return 0;
}

/*
 * Set internal ccache pointer, to be picked up when connecting
 */
int
pigeon_set_ccache(struct pigeon *cp, const char *ccache)
{
	if (!cp || !cp->ctx) {
		errno = EINVAL;
		return -1;
	}

	if (cp->ctx->ccache_name) {
		free(cp->ctx->ccache_name);
		cp->ctx->ccache_name = NULL;
	}

	if (ccache)
		cp->ctx->ccache_name = strdup(ccache);

	return 0;
}

void
pigeon_set_logging(int loglevel)
{
	__pigeon_verbose = loglevel;
}

void
pigeon_set_timeout(struct pigeon *p, time_t timeout)
{
	bufferevent_settimeout(p->bev, timeout, timeout);
	bufferevent_enable(p->bev, EV_READ);
}

void
pigeon_set_cleartext(struct pigeon *p, int noencrypt, int nosign)
{
	p->noencrypt = noencrypt;
	p->nosign = nosign;
}
