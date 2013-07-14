#!/bin/sh
# $Gateweaver: apigen.sh,v 1.11 2007/03/13 18:38:25 cvs Exp $
#
# Generates support functions that rely on ASN.1 definitions.  This makes
# the assumption that message functions will continue to be well named.
# If you change robin.asn1 severely, this will break similarly.
#
# Output:
# 	1	api C functions
#	3	api H headers

[[ -z $CURDIR ]] && CURDIR=`pwd`

MSGLIST=`grep ROBIN_MSG_ ${CURDIR}/robin.asn1 | \
		sed -e 's/ROBIN_MSG_//' -e 's/(\([0-9]\).*)*//'`

gen_preamble() {
	cat >&3 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_H
#define ROBIN_API_H
#include "robin.h"

__EOT
	cat <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#include <errno.h>
#include <stdlib.h>
#include "robin_locl.h"
#include <toolbox_asn1_der.h>
__EOT
}

gen_postamble() {
	cat >&3 <<__EOT

#endif
__EOT
}

gen_connect() {
	# HEADER
	cat << __EOT
/*
 * CONNECT PROCESS
 *
 * Take the gss_buffer from pigeon, and parse into normal functions, then shove
 * it down the throat of the connection callback.
 *
 * The state processor is required to either free, or delegate the command
 * structure memory to the user.
 */
void
robin_api_connect_process(struct pigeon *p, gss_buffer_desc *tok, void *arg)
{
	robin_con con = arg;
	unsigned char *buf;
	size_t len, plen, slen;
	int ret, tag;
	Der_class class;
	Der_type type;
	RobinHeader *hdr = NULL;

	len = tok->length;
	buf = tok->value;

	if (robin_verbose & (ROBIN_LOG_PROTO | ROBIN_LOG_PROTO_DUMP))
		log_debug("[ASN.1] %zu bytes", len);
	if (robin_verbose & ROBIN_LOG_PROTO_DUMP)
		log_hexdump(buf, len);

	while (len > 0) {
		if ((ret = tb_der_get_tag(buf, len, &class, &type, &tag, &plen)))
			goto out;
		if (robin_verbose & ROBIN_LOG_PROTO)
			log_debug("[ASN.1] class %d type %d tag %d size %zu",
					class, type, tag, plen);

		if (plen > len) {
			ret = ROBIN_MALICIOUS;
			goto out;
		}

		if (class != ASN1_C_APPL || type != CONS) {
			ret = ROBIN_UNIMPLEMENTED;
			log_warnx("asn.1 unimplemented class %d type %d tag %d size %zu",
					class, type, tag, plen);
			goto out;
		}

		/* the big honking switch! */
		hdr = NULL;
		slen = 0;
		switch ((ROBIN_MSGTYPE)tag) {
__EOT

	for msg in $MSGLIST ; do
		cat <<__EOT
			case ROBIN_MSG_${msg}:
				slen = sizeof(ROBIN_${msg});
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_${msg}(buf, len, (ROBIN_${msg} *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

__EOT
	done

	# FOOTER
	cat <<__EOT

				default:
					ret = ROBIN_API_INTERNAL;
					log_warnx("robin packet processor detected unhandled "
							"message type %d",
							tag);
					break;
			}

		/*
		 * packet is now decoded, and overloaded into (hdr).
		 */
		if (ret != ROBIN_SUCCESS)
			goto out;

		/* call the ENGINE, or the EXTERNAL PROCESSOR */
		if (con->context->cb.process) {
			con->context->cb.process(con->context, con, tag, hdr, slen,
					con->context->cb.arg);
			hdr = NULL;
		} else if (con->cb.process) {
			con->cb.process(con->context, con, tag, hdr, slen, con->cb.arg);
			hdr = NULL;
			log_debug("engineless process");
		} else
			log_debug("no process callback on connection");

		buf += plen;
		len -= plen;
	}

	return;

out:
	if (hdr)
		free(hdr);
	log_warnx("robin packet processor: class %d type %d tag %d size %zu: %s",
			class, type, tag, plen,
			robin_print_error(con->context, ret));
	log_info("[BAD ASN.1] %zu bytes", len);
	log_hexdump(buf, len);
	pigeon_set_shutdown(p);
}
__EOT
}

gen_state_process() {
	# HEADER
	cat <<__EOT
/*
 * RCB_PROCESS
 *
 * Do something with the messages received.  We are responsible to free the
 * memory allocated to the command in (hdr).  The callbacks MUST copy the
 * structure if they wish to use it after returning control.
 */
void
robin_api_state_process(robin_context context, robin_con con,
		ROBIN_MSGTYPE type, RobinHeader *hdr, size_t hlen, void *arg)
{
	int statematch = 0;
	int ret = ROBIN_CALLBACK_DONE;

	if (hdr == NULL)
		fatalx("robin_state_do_process no data");

	switch (type) {
__EOT

	# First processing handles the status messages

	for msg in $MSGLIST ; do
		if echo $msg | grep -e ^STATUS -e ^PONG >/dev/null; then
			cat <<__EOT
		case ROBIN_MSG_${msg}:
			if (hlen < sizeof(ROBIN_${msg})) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_${msg}));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

__EOT
		fi
	done

	# Second processing handles all other messages

	for msg in $MSGLIST ; do
		if ! echo $msg | grep -e ^STATUS -e ^PONG >/dev/null; then
		cat <<__EOT
		case ROBIN_MSG_${msg}:
__EOT
		fi
	done

	# Last bit of command for the other messages

	cat <<__EOT
			break;
__EOT

	# FOOTER
	cat <<__EOT

		default:
			ret = ROBIN_API_INTERNAL;
			log_warnx("robin state engine detected unhandled message type %d",
					type);
			break;
	}

	/* nothing matched, pass through to connection processor */
	if (statematch == 0) {
		if (con->cb.process)
			ret = con->cb.process(context, con, type, hdr, hlen, con->cb.arg);
		else
			ret = robin_status_reply(context, con, hdr->xid, ROBIN_UNIMPLEMENTED);
	}

out:
	/* free the message once the user is done with it */
	if (ret != ROBIN_CALLBACK_SAVEMSG)
		robin_api_state_free_msg(type, hdr, hlen);
}
__EOT
}

gen_state_free() {
	cat <<__EOT
/*
 * FREE
 *
 * Safely free the multiplexed message.  Complain if its mismatched, since it
 * means something is stomping on the robin_state argument.
 */
void
robin_api_state_free_msg(ROBIN_MSGTYPE type, RobinHeader *hdr, size_t len)
{
	switch (type) {
__EOT

	for msg in $MSGLIST ; do
		cat <<__EOT
		case ROBIN_MSG_${msg}:
			if (len != sizeof(ROBIN_${msg}))
				goto out;
			free_ROBIN_${msg}((ROBIN_${msg} *)hdr);
			free(hdr);
			break;

__EOT
	done

	cat <<__EOT
	}
	return;

out:
	log_warnx("robin_api_state_free_msg: MISMATCHED FREE!  type=%d len=%zu",
			type, len);
}
__EOT
}

gen_hostmsg() {
	for msg in $MSGLIST ; do
		msgname=`echo $msg | sed -e 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/'`
		if echo $msg | grep ^STATUS > /dev/null; then
			isrep="rep."
		else
			isrep=""
		fi

		cat >&3 <<__EOT
int robin_api_send_${msgname}(robin_context, robin_con, ROBIN_${msg} *, uint32_t *);
__EOT

		# PING and PONG are special
		[[ $msg == "PING" ]] && continue
		[[ $msg == "PONG" ]] && continue

		cat <<__EOT
int
robin_api_send_${msgname}(robin_context context, robin_con con, ROBIN_${msg} *msg, uint32_t *xid)
{
	char *buf = NULL;
	size_t buflen, len;
	int ret = ROBIN_SUCCESS;

	if (con == NULL || msg == NULL)
		return ROBIN_API_INVALID;
	if (!pigeon_isconnected(con->p))
		return ROBIN_DISCONNECTED;
	robin_header(context, con, &msg->${isrep}hdr);
	if (xid)
		*xid = msg->${isrep}hdr.xid;
	TBASN1_MALLOC_ENCODE(ROBIN_${msg}, buf, buflen, msg, &len, ret);
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

__EOT
	done
}

#
# Do the work in the following order
#

gen_preamble
echo
gen_connect
echo
gen_state_process
echo
gen_state_free
echo
gen_hostmsg
gen_postamble
