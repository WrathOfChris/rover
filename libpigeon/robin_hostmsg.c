/* $Gateweaver: robin_hostmsg.c,v 1.21 2006/04/08 19:36:59 cmaxwell Exp $ */
/*
 * Copyright (c) 2005 Christopher Maxwell.  All rights reserved.
 */
#include <errno.h>
#include <stdlib.h>
#include "robin_locl.h"

#ifndef lint
RCSID("$Gateweaver: robin_hostmsg.c,v 1.21 2006/04/08 19:36:59 cmaxwell Exp $");
#endif

/*
 * HOSTMSG
 * =======
 * The real commands to send a specific message down a specific pipe.  All
 * commands return success or failure based on the provided robin_con handle.
 * The header WILL BE MODIFIED by robin_header().
 *
 * ARGUMENTS
 * ---------
 * context	- robin_context handle
 * con		- robin_con connection handle
 * msg		- message structure, typed per-function
 * *xid		- pointer to a (uint32_t) that returns the transaction ID
 *
 * RETURNS
 * -------
 * ROBIN_API_INVALID	state argument was invalid
 * ROBIN_DISCONNECTED	connection was not in authenticated state
 * ROBIN_PIGEON			connection write failed in pigeon layer
 */

int
robin_api_send_ping(robin_context context, robin_con con, ROBIN_PING *msg, uint32_t *xid)
{
	char *buf = NULL;
	size_t buflen, len;
	int ret = ROBIN_SUCCESS;

	if (con == NULL || msg == NULL)
		return ROBIN_API_INVALID;
	if (!pigeon_isconnected(con->p))
		return ROBIN_DISCONNECTED;
	robin_header(context, con, &msg->hdr);
	if (xid)
		*xid = msg->hdr.xid;
	TBASN1_MALLOC_ENCODE(ROBIN_PING, buf, buflen, msg, &len, ret);
	if (ret == ROBIN_SUCCESS) {
		if (buflen != len)
			ret = ROBIN_ENCODER;
		else {
			if (pigeon_write(con->p, buf, len) == -1)
				ret = ROBIN_PIGEON;
		}
	}
	if (buf)
		free(buf);
	return ret;
}

int
robin_api_send_pong(robin_context context, robin_con con, ROBIN_PONG *msg, uint32_t *xid)
{
	char *buf = NULL;
	size_t buflen, len;
	int ret = ROBIN_SUCCESS;

	if (con == NULL || msg == NULL)
		return ROBIN_API_INVALID;
	if (!pigeon_isconnected(con->p))
		return ROBIN_DISCONNECTED;
	robin_header(context, con, &msg->rep.hdr);
	if (xid)
		*xid = msg->rep.hdr.xid;
	TBASN1_MALLOC_ENCODE(ROBIN_PONG, buf, buflen, msg, &len, ret);
	if (ret == ROBIN_SUCCESS) {
		if (buflen != len)
			ret = ROBIN_ENCODER;
		else {
			if (pigeon_write(con->p, buf, len) == -1)
				ret = ROBIN_PIGEON;
		}
	}
	if (buf)
		free(buf);
	return ret;
}
