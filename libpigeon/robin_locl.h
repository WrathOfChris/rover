/* $Gateweaver: robin_locl.h,v 1.32 2007/05/22 03:03:48 cmaxwell Exp $ */
#ifndef ROBIN_LOCL
#define ROBIN_LOCL
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <event.h>
#include <toolbox.h>
#include <toolbox_asn1.h>
#include "pigeon_locl.h"
#include "robin.h"
#include "robin_api.h"
#include "robin_api_msg.h"

#define ROBIN_ADD_CONTEXT(dst, ctx) do {\
	if ((ctx)) ((ctx)->refcount)++;		\
	(dst) = (ctx);						\
} while (0);

#define ROBIN_DEL_CONTEXT(dst, ctx) do {\
	if ((ctx)->refcount == 1)			\
		robin_free_context(ctx);		\
	if ((ctx)) ((ctx)->refcount)--;		\
	(dst) = NULL;						\
} while (0);

extern int robin_verbose;

typedef int RCB_STATE(robin_context, robin_con, RobinHeader *, uint32_t *);

struct robin_state {
	TAILQ_ENTRY(robin_state) entry;
	enum {
		STATE_RECV = 0x0001,			/* (REP) */
		STATE_SEND = 0x0002,			/* (REQ) */
		STATE_CELL = 0x0004,			/* any host in the cell */
		STATE_HOST = 0x0008,			/* specific host */
		STATE_CONN = 0x0010,			/* specific connection */
		STATE_SENT = 0x0020,			/* message has been sent */
		STATE_WAIT = 0x0040,			/* wait for a REPly */
		STATE_KEEP = 0x0080,			/* keep until timeout */
		STATE_HOLD = 0x0100,			/* being held by ptr, don't free */
		STATE_FREE = 0x0200				/* would have free'd, holder should */
	} state;
	uint32_t xid;						/* sent transaction ID */
	robin_context context;				/* context pointer */
	struct event timer;					/* transaction timer */

	/* sending state */
	RCB_STATE *sendfunc;				/* send function */
	ROBIN_MSGTYPE msgtype;				/* stored message type */
	RobinHeader *msg;					/* message, only header exposed */
	size_t msglen;						/* sanity length of message */

	/* callback arguments */
	robin_con con;						/* connection backpointer */
	const RobinHost *host;				/* host backpointer */
	RCB_STATUS *callback;				/* close enough */
	void *arg;							/* sender argument */
	int cbcount;
};

/* robin_api.c */
void robin_api_connect_process(struct pigeon *, gss_buffer_desc *, void *);
void robin_api_state_process(robin_context, robin_con,
		ROBIN_MSGTYPE, RobinHeader *, size_t, void *);
void robin_api_state_free_msg(ROBIN_MSGTYPE, RobinHeader *, size_t);

/* robin_connect.c */
void robin_connect_set_callbacks(robin_context, robin_con,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *, RCB_SHUTDOWN *, void *);
int robin_connect(robin_context,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *, RCB_SHUTDOWN *, void *);
int robin_connect_host(robin_context, const RobinHost *,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *, RCB_SHUTDOWN *, void *);
int robin_connect_socket(robin_context, int,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *, RCB_SHUTDOWN *, void *);

/* robin_state.c */
struct robin_state * robin_state_alloc(robin_context);
void robin_state_set_send(struct robin_state *,
		RCB_STATE *, ROBIN_MSGTYPE, RobinHeader *, size_t);
void robin_state_set_reply(struct robin_state *, robin_con, uint32_t,
		RCB_STATE *, ROBIN_MSGTYPE, RobinStatus *, size_t);
void robin_state_set_con(struct robin_state *, robin_con);
void robin_state_set_host(struct robin_state *, const RobinHost *);
void robin_state_set_waitreply(struct robin_state *,
	   	RCB_STATUS *, void *);
int robin_state_go(struct robin_state *);
int robin_state_find(robin_context, robin_con, uint32_t,
		struct robin_state **);
void robin_state_free(struct robin_state *);
void robin_state_abort(struct robin_state *, int);
void robin_state_resend(struct robin_state *);
int robin_state_rescan_rep(robin_context, robin_con, ROBIN_STATUS *, int *);

void robin_state_do_connect(robin_context, robin_con, int, void *);
void robin_state_do_accept(robin_context, robin_con, int, void *);
void robin_state_do_shutdown(robin_context, robin_con, int, void *);

#endif
