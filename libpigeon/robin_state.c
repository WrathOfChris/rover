/* $Gateweaver: robin_state.c,v 1.44 2007/05/22 03:03:48 cmaxwell Exp $ */
/*
 * Copyright (c) 2005 Christopher Maxwell.  All rights reserved.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "robin_locl.h"

#ifndef lint
RCSID("$Gateweaver: robin_state.c,v 1.44 2007/05/22 03:03:48 cmaxwell Exp $");
#endif

/*
 * LIFE OF A STATE
 * ===============
 *
 * 	-	API call creates a blank state entry marked RECV.  This is the default
 * 		to avoid accidentally sending during failure.
 * 	-	caller sets 'send' by unsetting RECV and setting SEND, along with flags
 * 		indicating the proper method of sending (CELL/HOST/CONN).  The message
 * 		structure is attached, at which point it must be forgotten by the
 * 		caller.
 * 	-	caller optionally sets callbacks if waiting for a reply
 *
 * 	-	API notifies the state engine to begin processing the state entry.
 *
 * 	-	replies, upon successfully calling 'GO' delete the original state entry
 */

static void robin_state_timeout(int, short, void *);
static void robin_state_free_int(struct robin_state *, int);

/*
 * ALLOC
 *
 * Allocate a state structure, link it to the context master state list.  The
 * default mode is STATE_RECV.
 */
struct robin_state *
robin_state_alloc(robin_context context)
{
	struct robin_state *rs;

	if (context == NULL)
		fatalx("state allocation without context");

	if ((rs = calloc(1, sizeof(*rs))) == NULL)
		return NULL;
	rs->state = STATE_RECV;
	ROBIN_ADD_CONTEXT(rs->context, context);
	evtimer_set(&rs->timer, robin_state_timeout, rs);
	TAILQ_INSERT_TAIL(&context->state, rs, entry);

	return rs;
}

/*
 * Set the SEND parameters for a state entry, including message.
 */
void
robin_state_set_send(struct robin_state *rs,
		RCB_STATE *sendfunc, ROBIN_MSGTYPE type, RobinHeader *msg, size_t len)
{
	rs->state &= ~STATE_RECV;
	rs->state |= STATE_SEND | STATE_CELL;
	rs->sendfunc = sendfunc;
	rs->msgtype = type;
	rs->msg = msg;
	rs->msglen = len;
}

/*
 * Set up state to send a reply to the originator.
 */
void
robin_state_set_reply(struct robin_state *rs, robin_con con, uint32_t xid,
		RCB_STATE *sendfunc, ROBIN_MSGTYPE type, RobinStatus *rep, size_t len)
{
	rep->rxid = xid;

	rs->state = (STATE_SEND | STATE_CONN);
	rs->sendfunc = sendfunc;
	robin_api_state_free_msg(rs->msgtype, rs->msg, rs->msglen);
	rs->msgtype = type;
	rs->msg = (RobinHeader *)rep;
	rs->msglen = len;
	rs->con = con;
}

void
robin_state_set_con(struct robin_state *rs, robin_con con)
{
	rs->state &= ~(STATE_CELL | STATE_HOST);
	rs->state |= STATE_CONN;
	rs->con = con;
}

void
robin_state_set_host(struct robin_state *rs, const RobinHost *host)
{
	rs->state &= ~(STATE_CELL | STATE_CONN);
	rs->state |= STATE_HOST;
	rs->host = host;
}

void
robin_state_set_waitreply(struct robin_state *rs,
		RCB_STATUS *callback, void *arg)
{
	if (callback || arg) {
		rs->state |= STATE_WAIT;
		rs->callback = callback;
		rs->arg = arg;
	}
}

/*
 * If the state entry is 'sendable', try to match it to a valid connection and
 * send it.
 *
 * This only works for STATE_CELL and STATE_HOST, since STATE_CON should
 * already be connected...
 */
static void
robin_state_scan_entry(struct robin_state *state, int doabort)
{
	robin_con con, con_n;
	int ret;
	int inprogress = 0, total = 0;

	if (robin_verbose & ROBIN_LOG_STATE)
		log_debug("==> STATE: scanning xid %u con %p (%s%s%s%s%s%s)",
				state->xid, state->con,
				state->state & STATE_RECV ? "R" : "-",
				state->state & STATE_SEND ? "s" : "-",
				state->state & STATE_CELL ? "C" : "-",
				state->state & STATE_HOST ? "H" : "-",
				state->state & STATE_CONN ? "c" : "-",
				state->state & STATE_SENT ? "S" : "-");

	/* nope, this little piggy is already gone */
	if (state->state & STATE_SENT)
		return;

	/* nope, this little piggy was a received message */
	if (state->state & STATE_RECV)
		return;

	/* nope, this little piggy wants his own connection */
	if (!(state->state & (STATE_CELL | STATE_HOST)) && state->con == NULL)
		return;

	/* nope, this little piggy's already sent */
	if (state->con != NULL && !(state->state & STATE_CONN))
		return;

	for (con = TAILQ_FIRST(&state->context->con.list);
			con != TAILQ_END(&state->context->con.list);
			con = con_n) {
		con_n = TAILQ_NEXT(con, entry);

		if (robin_verbose & ROBIN_LOG_STATE)
			log_debug("==> STATE: trying con %p cs %x", con,
					con->connect.state);

		/* track connection progress */
		++total;
		switch (con->connect.state) {
			case CONNECT_LOOKUP_SRV:
			case CONNECT_LOOKUP_A:
			case CONNECT_ING:
				++inprogress;
				continue;
			case CONNECT_FAIL:
			case CONNECT_TIMEDOUT:
				/*
				 * Dangerous waters ahead.  If this state is a STATE_CONN and
				 * has the connection set, then shutting down the connection
				 * will abort and free the structure we are iterating in.
				 * Unset the connection and allow it to be resent.
				 */
				if (state->con == con)
					state->con = NULL;
				robin_shutdown_con(state->context, con);
				continue;
			case CONNECT_ED:
				++inprogress;
				break;
		}

		/* try to send only back down the same connection */
		if ((state->state & STATE_CONN) && state->con != NULL)
			if (con == state->con) {
				if ((ret = state->sendfunc(state->context, state->con,
								state->msg, &state->xid))) {
					log_warnx("robin tried to scan&send conn but failed: %s",
							robin_print_error(state->context, ret));
					state->con = NULL;
				} else {
					/* sent ok, go we-we-we-we all the way home */
					state->state |= STATE_SENT;

					if (robin_verbose & ROBIN_LOG_STATE)
						log_debug("==> STATE: sent xid %u", state->xid);

					/* free the state entry if not waiting for a reply */
					if (!(state->state & STATE_WAIT)) {
						if (state->state & STATE_HOLD)
							state->state |= STATE_FREE;
						else
							robin_state_free(state);
					}

					return;
				}
			}

		/* try to send by host */
		if ((state->state & STATE_HOST) && state->host != NULL)
			if (con->host && con->host->hostname &&
					state->host && state->host->hostname &&
					strcmp(con->host->hostname, state->host->hostname) == 0) {
				state->con = con;
				if ((ret = state->sendfunc(state->context, state->con,
								state->msg, &state->xid))) {
					log_warnx("robin tried to scan&send host but failed: %s",
							robin_print_error(state->context, ret));
					state->con = NULL;
				} else {
					/* sent ok, go we-we-we-we all the way home */
					state->state |= STATE_SENT;

					if (robin_verbose & ROBIN_LOG_STATE)
						log_debug("==> STATE: sent xid %u", state->xid);

					/* free the state entry if not waiting for a reply */
					if (!(state->state & STATE_WAIT)) {
						if (state->state & STATE_HOLD)
							state->state |= STATE_FREE;
						else
							robin_state_free(state);
					}

					return;
				}
			}

		/* try to send by cell */
		if ((state->state & STATE_CELL)) {
			state->con = con;
			if ((ret = state->sendfunc(state->context, state->con,
							state->msg, &state->xid))) {
				log_warnx("robin tried to scan&send cell but failed: %s",
						robin_print_error(state->context, ret));
				state->con = NULL;
			} else {
				/* sent ok, go we-we-we-we all the way home */
				state->state |= STATE_SENT;

				if (robin_verbose & ROBIN_LOG_STATE)
					log_debug("==> STATE: sent xid %u", state->xid);

				/* free the state entry if not waiting for a reply */
				if (!(state->state & STATE_WAIT)) {
					if (state->state & STATE_HOLD)
						state->state |= STATE_FREE;
					else
						robin_state_free(state);
				}

				return;
			}
		}
	}

	/* state did not get sent, something must be wrong */
	if (inprogress == 0 && total > 0 && !(state->state & STATE_SENT)) {
		if (!doabort)
			return;
		if (errno == EAUTH || errno == ENEEDAUTH)
			robin_state_abort(state, ROBIN_PIGEON);
		else
			robin_state_abort(state, ROBIN_HOSTDOWN);
	}
}

/*
 * Scan through all state entries in the context state list.  Send any that
 * match open connections.  Their internal timers
 */
static void
robin_state_scan(robin_context context, int doabort)
{
	struct robin_state *rs, *rs_n;

	/* because state might be removed within */
	for (rs = TAILQ_FIRST(&context->state);
			rs != TAILQ_END(&context->state);
			rs = rs_n) {
		rs_n = TAILQ_NEXT(rs, entry);
		robin_state_scan_entry(rs, doabort);
	}
}

/*
 * This is used only by robin_api_state_process to rescan state messages that
 * may need to be resent.  The entire list must be scanned in case a duplicate
 * xid exists that must be serviced.
 */
int
robin_state_rescan_rep(robin_context context, robin_con con,
		ROBIN_STATUS *rep, int *match)
{
	struct robin_state *rs, *rs_n;
	int statematch = 0;
	int ret = ROBIN_CALLBACK_DONE;

	for (rs = TAILQ_FIRST(&con->context->state);
			rs != TAILQ_END(&con->context->state);
			rs = rs_n) {
		rs_n = TAILQ_NEXT(rs, entry);
		if (robin_verbose & ROBIN_LOG_STATE)
			log_debug("==> STATE: checking xid %u (%s%s%s%s%s%s)",
					rs->xid,
					rs->state & STATE_RECV ? "R" : "-",
					rs->state & STATE_SEND ? "s" : "-",
					rs->state & STATE_CELL ? "C" : "-",
					rs->state & STATE_HOST ? "H" : "-",
					rs->state & STATE_CONN ? "c" : "-",
					rs->state & STATE_SENT ? "S" : "-");
		if ((rs->state & STATE_SENT) && rep->rep.rxid == rs->xid) {
			statematch = 1;
			if (rs->callback && rs->cbcount == 0) {
				++rs->cbcount;
				ret = rs->callback(context, con, rep, rs->arg);
				/* do not free state on requested resend */
				if (ret == ROBIN_CALLBACK_RESEND) {
					--rs->cbcount;
					robin_state_resend(rs);
				} else if (ret == ROBIN_CALLBACK_ADDITIONAL) {
					--rs->cbcount;
				} else if (!(rs->state & STATE_KEEP)) {
					/*
					 * Free state only on SAVEMSG
					 * Do not free state or msg on ADDITIONAL
					 */
					if (ret == ROBIN_CALLBACK_SAVEMSG)
						robin_state_free_int(rs, 0);
					else if (ret != ROBIN_CALLBACK_ADDITIONAL)
						robin_state_free(rs);
				}
			} else if (rs->callback == NULL) {
				if (robin_verbose & ROBIN_LOG_STATE)
					log_debug("==> STATE: no callback");
				/*
				 * Free state only on SAVEMSG
				 * Do not free state or msg on ADDITIONAL
				 */
				if (ret == ROBIN_CALLBACK_SAVEMSG)
					robin_state_free_int(rs, 0);
				else if (ret != ROBIN_CALLBACK_ADDITIONAL)
/* XXX */			robin_state_free(rs);
			} else
				log_debug("==> STATE: callback already called?");
		}
	}

	if (match)
		*match = statematch;
	return ret;
}

/*
 * RCB_CONNECT
 *
 * The robin_con has likely failed.  Do any required cleanup and call through
 * to the EXTERNAL processor if available.
 */
void
robin_state_do_connect(robin_context context, robin_con con, int ret,
		void *arg)
{
	int inprogress = 0;
	robin_con rc;
	struct robin_state *rs, *rs_n;

	if (robin_verbose & ROBIN_LOG_STATE)
		log_debug("==> STATE: connect con=%p cs=%x error:%s", con,
				con->connect.state, robin_print_error(context, ret));

	if (ret == ROBIN_SUCCESS)
		log_warnx("robin_state_do_connect: succeeded??? how???");
	else
		con->connect.state = CONNECT_FAIL;

	/* EXTERNAL */
	if (con && con->cb.connect)
		con->cb.connect(context, con, ret, con->cb.arg);

	robin_state_scan(context, 1);

	/* scan connections again, see if any others could succeed */
	TAILQ_FOREACH(rc, &context->con.list, entry)
		if (rc->connect.state == CONNECT_LOOKUP_SRV
				|| rc->connect.state == CONNECT_LOOKUP_A
				|| rc->connect.state == CONNECT_ING)
			++inprogress;
	if (inprogress > 0)
		return;

	/* ok, none will succeed loop through an abort sequence */
	for (rs = TAILQ_FIRST(&context->state);
			rs != TAILQ_END(&context->state);
			rs = rs_n) {
		rs_n = TAILQ_NEXT(rs, entry);
		robin_state_abort(rs, ROBIN_NOHOSTS);
	}
}

/*
 * RCB_ACCEPT
 *
 * The robin_con is either successfully authenticated, or has failed.  If it
 * worked, loop through the state entries and send any that fit this con.
 */
void
robin_state_do_accept(robin_context context, robin_con con, int ret,
		void *arg)
{
	if (robin_verbose & ROBIN_LOG_STATE)
		log_debug("==> STATE: accept con=%p error:%s", con,
				robin_print_error(context, ret));

	robin_state_scan(context, 1);

	/* EXTERNAL */
	if (con && con->cb.accept)
		con->cb.accept(context, con, ret, con->cb.arg);
}

/*
 * RCB_SHUTDOWN
 *
 * Clean up anything necessary, then call the external processor
 */
void
robin_state_do_shutdown(robin_context context, robin_con con, int ret,
		void *arg)
{
	struct robin_state *rs, *rs_n;

	if (robin_verbose & ROBIN_LOG_STATE)
		log_debug("==> STATE: shutdown con=%p error:%s", con,
				robin_print_error(context, ret));

	/* EXTERNAL */
	if (con && con->cb.shutdown)
		con->cb.shutdown(context, con, ret, con->cb.arg);

	for (rs = TAILQ_FIRST(&context->state);
			rs != TAILQ_END(&context->state);
			rs = rs_n) {
		rs_n = TAILQ_NEXT(rs, entry);
		if ((rs->state & STATE_SENT) && rs->con == con) {
			/* if the state entry was connection-only, abort it */
			if (rs->state & STATE_CONN)
				robin_state_abort(rs, ECONNRESET);
			else
				robin_state_resend(rs);
		}
	}
}

/*
 * GO!
 *
 * At the end of this function, the state machine takes control over the entry.
 * From here on in, nothing else should touch it.
 *
 * The state machine is responsible for triggering connects to appropriate
 * servers.  Use the state flags to change its behavior.
 *
 * States are preferential from the MOST specific to the LEAST specific.  For
 * example, (STATE_CONN | STATE_CELL) will prefer the connection within the
 * state entry, but MAY fall back to any connection in the cell.
 *
 * Once robin_state_go is called, the state engine OWNS THE STATE.  IT MUST NOT
 * BE FREED ON ERROR BY THE CALLER.
 */
int
robin_state_go(struct robin_state *rs)
{
	int ret, inprogress = 0;
	robin_con con;

	/* start the clock */
	event_add(&rs->timer, &rs->context->tv_cmdtimeout);

	rs->state |= STATE_HOLD;
	robin_state_scan(rs->context, 0);
	rs->state &= ~STATE_HOLD;

	/* scanner is done with state, but was nice enough not to free it */
	if (rs->state & STATE_FREE) {
		robin_state_free(rs);
		return 0;
	}

	/* scan connections again, only start again if none are in progress */
	TAILQ_FOREACH(con, &rs->context->con.list, entry)
		if (con->connect.state == CONNECT_LOOKUP_SRV
				|| con->connect.state == CONNECT_LOOKUP_A
				|| con->connect.state == CONNECT_ING)
			++inprogress;
	if (inprogress > 0)
		return ROBIN_SUCCESS;

	/* didn't get sent, must mean no connections are ready */
	if (rs->con == NULL && !(rs->state & STATE_SENT)) {
		if (rs->host) {
			if (robin_verbose & ROBIN_LOG_STATE)
				log_debug("GO: connecting to specified host...");
			if ((ret = robin_connect_host(rs->context, rs->host,
							rs->context->defcb.connect,		/* connect */
							rs->context->defcb.accept,		/* accept */
							rs->context->defcb.process,		/* process */
							rs->context->defcb.shutdown,	/* shutdown */
							rs->context->defcb.arg))) {
				log_warnx("GO failed: %s",
						robin_print_error(rs->context, ret));
				robin_state_free(rs);
				return ret;
			}
		} else if (rs->context->con.sfd != -1) {
			if (robin_verbose & ROBIN_LOG_STATE)
				log_debug("GO: connecting to specified socket...");
			if ((ret = robin_connect_socket(rs->context, rs->context->con.sfd,
							rs->context->defcb.connect,		/* connect */
							rs->context->defcb.accept,		/* accept */
							rs->context->defcb.process,		/* process */
							rs->context->defcb.shutdown,	/* shutdown */
							rs->context->defcb.arg))) {
				log_warnx("GO failed: %s",
						robin_print_error(rs->context, ret));
				robin_state_free(rs);
				return ret;
			}
		} else {
			if (robin_verbose & ROBIN_LOG_STATE)
				log_debug("GO: connecting to cell...");
			if ((ret = robin_connect(rs->context,
							rs->context->defcb.connect,		/* connect */
							rs->context->defcb.accept,		/* accept */
							rs->context->defcb.process,		/* process */
							rs->context->defcb.shutdown,	/* shutdown */
							rs->context->defcb.arg))) {
				log_warnx("GO failed: %s",
						robin_print_error(rs->context, ret));
				robin_state_free(rs);
				return ret;
			}
		}
	}

	return ROBIN_SUCCESS;
}

/*
 * Find a state entry based on (xid).  If con is provided, match con as well.
 */
int
robin_state_find(robin_context context, robin_con con, uint32_t xid,
		struct robin_state **rs)
{
	struct robin_state *s;

	if (context == NULL || rs == NULL)
		return ROBIN_API_INVALID;

	TAILQ_FOREACH(s, &context->state, entry)
		if (s->xid == xid) {
			if (con && s->con != con)
				continue;
			*rs = s;
			return ROBIN_SUCCESS;
		}

	return ROBIN_NOTFOUND;
}

/*
 * TIMEOUT
 *
 * No reply within the allowed command timeout.  Abort.  This notifies the
 * original caller.
 */
static void
robin_state_timeout(int fd, short which, void *arg)
{
	struct robin_state *state = arg;

	if (robin_verbose & ROBIN_LOG_STATE)
		log_debug("==> STATE: shutdown xid %u con %p", state->xid, state->con);

	robin_state_abort(state, ROBIN_TIMEOUT);
}

/*
 * FREE
 *
 * Free the robin_state, removing the state timer.  Do not trigger the
 * callback.
 */
static void
robin_state_free_int(struct robin_state *rs, int freemsg)
{
	struct timeval tv_stop, tv_now, tv_diff;

	if (robin_verbose & ROBIN_LOG_STATE)
		log_debug("==> STATE: freeing xid %u con %p", rs->xid, rs->con);

	TAILQ_REMOVE(&rs->context->state, rs, entry);
	if (evtimer_pending(&rs->timer, &tv_stop)) {
		evtimer_del(&rs->timer);

		if (robin_verbose & (ROBIN_LOG_STATE | ROBIN_LOG_STATE_TIMING)) {
			gettimeofday(&tv_now, NULL);
			timersub(&tv_stop, &tv_now, &tv_diff);
			timersub(&rs->context->tv_cmdtimeout, &tv_diff, &tv_stop);
			log_debug("==> STATE: completed type %u xid %u in %lu.%06lus",
					rs->msgtype, rs->xid, tv_stop.tv_sec, tv_stop.tv_usec);
		}
	}
	ROBIN_DEL_CONTEXT(rs->context, rs->context);
	if (freemsg)
		robin_api_state_free_msg(rs->msgtype, rs->msg, rs->msglen);
	free(rs);
}

void
robin_state_free(struct robin_state *rs)
{
	robin_state_free_int(rs, 1);
}

/*
 * ABORT
 *
 * Run the callback, with ret as the code.  If ret is zero, use TIMEDOUT.  Then
 * destroy the state entry.
 */
void
robin_state_abort(struct robin_state *rs, int ret)
{
	ROBIN_STATUS_STORAGE msg;
	int sret = ROBIN_CALLBACK_DONE;
	int dontfree = (rs->state & STATE_HOLD);

	if (ret == 0)
		ret = ROBIN_TIMEOUT;

	/* fake a status reply */
	bzero(&msg, sizeof(msg));
	msg.status.rep.status = ret;

	/* set the HOLD marker to keep it from being freed */
	rs->state |= STATE_HOLD;

	if (rs->callback && rs->cbcount == 0) {
		++rs->cbcount;
		sret = rs->callback(rs->context, rs->con, (ROBIN_STATUS *)&msg,
				rs->arg);
	} else if (rs->callback)
		log_debug("==> STATE: callback already called?  want to abort");
	if (sret == ROBIN_CALLBACK_RESEND) {
		--rs->cbcount;
		robin_state_resend(rs);
		return;
	} else if (sret == ROBIN_CALLBACK_SAVEMSG) {
		robin_state_free_int(rs, 0);
		return;
	} else if (sret == ROBIN_CALLBACK_ADDITIONAL) {
		--rs->cbcount;
		return;
	}

	/* hold was set before we got to it, must not free */
	if (dontfree) {
		rs->state |= STATE_FREE;
		return;
	}

	robin_state_free(rs);
}

void
robin_state_resend(struct robin_state *rs)
{
	/* unset SENT, since it needs to resend */
	rs->state &= ~STATE_SENT;
	/* unset con, if not connection directed */
	if (!(rs->state & STATE_CONN))
		rs->con = NULL;
	robin_state_scan_entry(rs, 1);
}
