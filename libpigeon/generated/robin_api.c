/* $Gateweaver$ */
/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */
#include <errno.h>
#include <stdlib.h>
#include "robin_locl.h"
#include <toolbox_asn1_der.h>

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
			case ROBIN_MSG_GETROOT:
				slen = sizeof(ROBIN_GETROOT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETROOT(buf, len, (ROBIN_GETROOT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETROUTE:
				slen = sizeof(ROBIN_GETROUTE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETROUTE(buf, len, (ROBIN_GETROUTE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETDISK:
				slen = sizeof(ROBIN_GETDISK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETDISK(buf, len, (ROBIN_GETDISK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETCLIENT:
				slen = sizeof(ROBIN_GETCLIENT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETCLIENT(buf, len, (ROBIN_GETCLIENT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETOID:
				slen = sizeof(ROBIN_GETOID);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETOID(buf, len, (ROBIN_GETOID *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_SETOID:
				slen = sizeof(ROBIN_SETOID);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_SETOID(buf, len, (ROBIN_SETOID *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETLOCK:
				slen = sizeof(ROBIN_GETLOCK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETLOCK(buf, len, (ROBIN_GETLOCK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETACTION:
				slen = sizeof(ROBIN_GETACTION);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETACTION(buf, len, (ROBIN_GETACTION *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETTRANS:
				slen = sizeof(ROBIN_GETTRANS);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETTRANS(buf, len, (ROBIN_GETTRANS *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PING:
				slen = sizeof(ROBIN_PING);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PING(buf, len, (ROBIN_PING *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PONG:
				slen = sizeof(ROBIN_PONG);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PONG(buf, len, (ROBIN_PONG *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_SETCLIENTID:
				slen = sizeof(ROBIN_SETCLIENTID);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_SETCLIENTID(buf, len, (ROBIN_SETCLIENTID *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_SETCON:
				slen = sizeof(ROBIN_SETCON);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_SETCON(buf, len, (ROBIN_SETCON *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISCONNECT:
				slen = sizeof(ROBIN_DISCONNECT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISCONNECT(buf, len, (ROBIN_DISCONNECT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_REFRESH:
				slen = sizeof(ROBIN_REFRESH);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_REFRESH(buf, len, (ROBIN_REFRESH *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUS:
				slen = sizeof(ROBIN_STATUS);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUS(buf, len, (ROBIN_STATUS *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSHDL:
				slen = sizeof(ROBIN_STATUSHDL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSHDL(buf, len, (ROBIN_STATUSHDL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSHDLSUM:
				slen = sizeof(ROBIN_STATUSHDLSUM);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSHDLSUM(buf, len, (ROBIN_STATUSHDLSUM *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSROUTE:
				slen = sizeof(ROBIN_STATUSROUTE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSROUTE(buf, len, (ROBIN_STATUSROUTE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSLOCK:
				slen = sizeof(ROBIN_STATUSLOCK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSLOCK(buf, len, (ROBIN_STATUSLOCK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSINFO:
				slen = sizeof(ROBIN_STATUSINFO);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSINFO(buf, len, (ROBIN_STATUSINFO *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSACL:
				slen = sizeof(ROBIN_STATUSACL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSACL(buf, len, (ROBIN_STATUSACL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSDATA:
				slen = sizeof(ROBIN_STATUSDATA);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSDATA(buf, len, (ROBIN_STATUSDATA *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSDIRENT:
				slen = sizeof(ROBIN_STATUSDIRENT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSDIRENT(buf, len, (ROBIN_STATUSDIRENT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSTOKEN:
				slen = sizeof(ROBIN_STATUSTOKEN);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSTOKEN(buf, len, (ROBIN_STATUSTOKEN *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSDISK:
				slen = sizeof(ROBIN_STATUSDISK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSDISK(buf, len, (ROBIN_STATUSDISK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSHOST:
				slen = sizeof(ROBIN_STATUSHOST);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSHOST(buf, len, (ROBIN_STATUSHOST *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSGROUP:
				slen = sizeof(ROBIN_STATUSGROUP);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSGROUP(buf, len, (ROBIN_STATUSGROUP *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSOID:
				slen = sizeof(ROBIN_STATUSOID);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSOID(buf, len, (ROBIN_STATUSOID *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSPROTECT:
				slen = sizeof(ROBIN_STATUSPROTECT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSPROTECT(buf, len, (ROBIN_STATUSPROTECT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_STATUSSYNC:
				slen = sizeof(ROBIN_STATUSSYNC);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_STATUSSYNC(buf, len, (ROBIN_STATUSSYNC *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_MKNODE:
				slen = sizeof(ROBIN_MKNODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_MKNODE(buf, len, (ROBIN_MKNODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_MKSYM:
				slen = sizeof(ROBIN_MKSYM);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_MKSYM(buf, len, (ROBIN_MKSYM *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_OPEN:
				slen = sizeof(ROBIN_OPEN);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_OPEN(buf, len, (ROBIN_OPEN *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_UNLOCK:
				slen = sizeof(ROBIN_UNLOCK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_UNLOCK(buf, len, (ROBIN_UNLOCK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETATTR:
				slen = sizeof(ROBIN_GETATTR);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETATTR(buf, len, (ROBIN_GETATTR *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PUTATTR:
				slen = sizeof(ROBIN_PUTATTR);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PUTATTR(buf, len, (ROBIN_PUTATTR *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GETACL:
				slen = sizeof(ROBIN_GETACL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GETACL(buf, len, (ROBIN_GETACL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PUTACL:
				slen = sizeof(ROBIN_PUTACL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PUTACL(buf, len, (ROBIN_PUTACL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_READ:
				slen = sizeof(ROBIN_READ);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_READ(buf, len, (ROBIN_READ *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_WRITE:
				slen = sizeof(ROBIN_WRITE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_WRITE(buf, len, (ROBIN_WRITE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_APPEND:
				slen = sizeof(ROBIN_APPEND);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_APPEND(buf, len, (ROBIN_APPEND *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_START:
				slen = sizeof(ROBIN_TRANS_START);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_START(buf, len, (ROBIN_TRANS_START *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_WRITE:
				slen = sizeof(ROBIN_TRANS_WRITE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_WRITE(buf, len, (ROBIN_TRANS_WRITE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_APPEND:
				slen = sizeof(ROBIN_TRANS_APPEND);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_APPEND(buf, len, (ROBIN_TRANS_APPEND *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_READ:
				slen = sizeof(ROBIN_TRANS_READ);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_READ(buf, len, (ROBIN_TRANS_READ *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_FINISH:
				slen = sizeof(ROBIN_TRANS_FINISH);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_FINISH(buf, len, (ROBIN_TRANS_FINISH *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_ABORT:
				slen = sizeof(ROBIN_TRANS_ABORT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_ABORT(buf, len, (ROBIN_TRANS_ABORT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TRANS_SYNC:
				slen = sizeof(ROBIN_TRANS_SYNC);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TRANS_SYNC(buf, len, (ROBIN_TRANS_SYNC *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_PUT:
				slen = sizeof(ROBIN_NODE_PUT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_PUT(buf, len, (ROBIN_NODE_PUT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_DEL:
				slen = sizeof(ROBIN_NODE_DEL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_DEL(buf, len, (ROBIN_NODE_DEL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_COW:
				slen = sizeof(ROBIN_NODE_COW);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_COW(buf, len, (ROBIN_NODE_COW *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_SYNC:
				slen = sizeof(ROBIN_NODE_SYNC);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_SYNC(buf, len, (ROBIN_NODE_SYNC *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_XFER:
				slen = sizeof(ROBIN_NODE_XFER);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_XFER(buf, len, (ROBIN_NODE_XFER *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_SNAP:
				slen = sizeof(ROBIN_NODE_SNAP);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_SNAP(buf, len, (ROBIN_NODE_SNAP *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_NODE_GETSUM:
				slen = sizeof(ROBIN_NODE_GETSUM);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_NODE_GETSUM(buf, len, (ROBIN_NODE_GETSUM *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_LOOKUP:
				slen = sizeof(ROBIN_LOOKUP);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_LOOKUP(buf, len, (ROBIN_LOOKUP *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_READDIR:
				slen = sizeof(ROBIN_READDIR);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_READDIR(buf, len, (ROBIN_READDIR *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRLINK:
				slen = sizeof(ROBIN_DIRLINK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRLINK(buf, len, (ROBIN_DIRLINK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRUNLINK:
				slen = sizeof(ROBIN_DIRUNLINK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRUNLINK(buf, len, (ROBIN_DIRUNLINK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRRELINK:
				slen = sizeof(ROBIN_DIRRELINK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRRELINK(buf, len, (ROBIN_DIRRELINK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRCREATE:
				slen = sizeof(ROBIN_DIRCREATE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRCREATE(buf, len, (ROBIN_DIRCREATE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRSYMLINK:
				slen = sizeof(ROBIN_DIRSYMLINK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRSYMLINK(buf, len, (ROBIN_DIRSYMLINK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRRENAME:
				slen = sizeof(ROBIN_DIRRENAME);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRRENAME(buf, len, (ROBIN_DIRRENAME *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRHISTGET:
				slen = sizeof(ROBIN_DIRHISTGET);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRHISTGET(buf, len, (ROBIN_DIRHISTGET *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DIRHISTSET:
				slen = sizeof(ROBIN_DIRHISTSET);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DIRHISTSET(buf, len, (ROBIN_DIRHISTSET *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_CREATE:
				slen = sizeof(ROBIN_GROUP_CREATE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_CREATE(buf, len, (ROBIN_GROUP_CREATE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_DELETE:
				slen = sizeof(ROBIN_GROUP_DELETE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_DELETE(buf, len, (ROBIN_GROUP_DELETE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_MODIFY:
				slen = sizeof(ROBIN_GROUP_MODIFY);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_MODIFY(buf, len, (ROBIN_GROUP_MODIFY *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_RENAME:
				slen = sizeof(ROBIN_GROUP_RENAME);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_RENAME(buf, len, (ROBIN_GROUP_RENAME *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_ADD:
				slen = sizeof(ROBIN_GROUP_ADD);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_ADD(buf, len, (ROBIN_GROUP_ADD *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_DEL:
				slen = sizeof(ROBIN_GROUP_DEL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_DEL(buf, len, (ROBIN_GROUP_DEL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_GET:
				slen = sizeof(ROBIN_GROUP_GET);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_GET(buf, len, (ROBIN_GROUP_GET *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_PUT:
				slen = sizeof(ROBIN_GROUP_PUT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_PUT(buf, len, (ROBIN_GROUP_PUT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_GROUP_EVAL:
				slen = sizeof(ROBIN_GROUP_EVAL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_GROUP_EVAL(buf, len, (ROBIN_GROUP_EVAL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_PART:
				slen = sizeof(ROBIN_IHAVE_PART);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_PART(buf, len, (ROBIN_IHAVE_PART *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_VOLUME:
				slen = sizeof(ROBIN_IHAVE_VOLUME);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_VOLUME(buf, len, (ROBIN_IHAVE_VOLUME *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_NODE:
				slen = sizeof(ROBIN_IHAVE_NODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_NODE(buf, len, (ROBIN_IHAVE_NODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_ROUTE:
				slen = sizeof(ROBIN_IHAVE_ROUTE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_ROUTE(buf, len, (ROBIN_IHAVE_ROUTE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_FINISHED:
				slen = sizeof(ROBIN_IHAVE_FINISHED);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_FINISHED(buf, len, (ROBIN_IHAVE_FINISHED *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_GROUP:
				slen = sizeof(ROBIN_IHAVE_GROUP);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_GROUP(buf, len, (ROBIN_IHAVE_GROUP *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_TRANS:
				slen = sizeof(ROBIN_IHAVE_TRANS);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_TRANS(buf, len, (ROBIN_IHAVE_TRANS *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_WITHDRAW:
				slen = sizeof(ROBIN_IHAVE_WITHDRAW);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_WITHDRAW(buf, len, (ROBIN_IHAVE_WITHDRAW *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_IHAVE_PROTECT:
				slen = sizeof(ROBIN_IHAVE_PROTECT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_IHAVE_PROTECT(buf, len, (ROBIN_IHAVE_PROTECT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_GETROOT:
				slen = sizeof(ROBIN_VOLUME_GETROOT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_GETROOT(buf, len, (ROBIN_VOLUME_GETROOT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_SETROOT:
				slen = sizeof(ROBIN_VOLUME_SETROOT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_SETROOT(buf, len, (ROBIN_VOLUME_SETROOT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_CREATE:
				slen = sizeof(ROBIN_VOLUME_CREATE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_CREATE(buf, len, (ROBIN_VOLUME_CREATE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_MKNODE:
				slen = sizeof(ROBIN_VOLUME_MKNODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_MKNODE(buf, len, (ROBIN_VOLUME_MKNODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_CHNODE:
				slen = sizeof(ROBIN_VOLUME_CHNODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_CHNODE(buf, len, (ROBIN_VOLUME_CHNODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_STNODE:
				slen = sizeof(ROBIN_VOLUME_STNODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_STNODE(buf, len, (ROBIN_VOLUME_STNODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_RMNODE:
				slen = sizeof(ROBIN_VOLUME_RMNODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_RMNODE(buf, len, (ROBIN_VOLUME_RMNODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_SNAPSHOT:
				slen = sizeof(ROBIN_VOLUME_SNAPSHOT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_SNAPSHOT(buf, len, (ROBIN_VOLUME_SNAPSHOT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_DIRLINK:
				slen = sizeof(ROBIN_VOLUME_DIRLINK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_DIRLINK(buf, len, (ROBIN_VOLUME_DIRLINK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_DIRUNLINK:
				slen = sizeof(ROBIN_VOLUME_DIRUNLINK);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_DIRUNLINK(buf, len, (ROBIN_VOLUME_DIRUNLINK *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_VRNODE:
				slen = sizeof(ROBIN_VOLUME_VRNODE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_VRNODE(buf, len, (ROBIN_VOLUME_VRNODE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_VRSIZE:
				slen = sizeof(ROBIN_VOLUME_VRSIZE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_VRSIZE(buf, len, (ROBIN_VOLUME_VRSIZE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_RACL:
				slen = sizeof(ROBIN_VOLUME_RACL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_RACL(buf, len, (ROBIN_VOLUME_RACL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_VOLUME_WACL:
				slen = sizeof(ROBIN_VOLUME_WACL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_VOLUME_WACL(buf, len, (ROBIN_VOLUME_WACL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TOKEN_VERIFY:
				slen = sizeof(ROBIN_TOKEN_VERIFY);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TOKEN_VERIFY(buf, len, (ROBIN_TOKEN_VERIFY *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TOKEN_PUT:
				slen = sizeof(ROBIN_TOKEN_PUT);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TOKEN_PUT(buf, len, (ROBIN_TOKEN_PUT *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TOKEN_GET:
				slen = sizeof(ROBIN_TOKEN_GET);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TOKEN_GET(buf, len, (ROBIN_TOKEN_GET *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_TOKEN_DEL:
				slen = sizeof(ROBIN_TOKEN_DEL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_TOKEN_DEL(buf, len, (ROBIN_TOKEN_DEL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_COMPOUND:
				slen = sizeof(ROBIN_COMPOUND);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_COMPOUND(buf, len, (ROBIN_COMPOUND *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISK_INITIALIZE:
				slen = sizeof(ROBIN_DISK_INITIALIZE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISK_INITIALIZE(buf, len, (ROBIN_DISK_INITIALIZE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISK_MODIFY:
				slen = sizeof(ROBIN_DISK_MODIFY);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISK_MODIFY(buf, len, (ROBIN_DISK_MODIFY *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISK_RECOVER:
				slen = sizeof(ROBIN_DISK_RECOVER);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISK_RECOVER(buf, len, (ROBIN_DISK_RECOVER *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISK_BALANCE:
				slen = sizeof(ROBIN_DISK_BALANCE);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISK_BALANCE(buf, len, (ROBIN_DISK_BALANCE *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISK_POWERUP:
				slen = sizeof(ROBIN_DISK_POWERUP);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISK_POWERUP(buf, len, (ROBIN_DISK_POWERUP *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_DISK_POWERDOWN:
				slen = sizeof(ROBIN_DISK_POWERDOWN);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_DISK_POWERDOWN(buf, len, (ROBIN_DISK_POWERDOWN *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PROTECT_GET:
				slen = sizeof(ROBIN_PROTECT_GET);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PROTECT_GET(buf, len, (ROBIN_PROTECT_GET *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PROTECT_ADD:
				slen = sizeof(ROBIN_PROTECT_ADD);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PROTECT_ADD(buf, len, (ROBIN_PROTECT_ADD *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;

			case ROBIN_MSG_PROTECT_DEL:
				slen = sizeof(ROBIN_PROTECT_DEL);
				if ((hdr = malloc(slen)) == NULL)
					ret = ROBIN_API_NOMEM;
				else {
					ret = dec_ROBIN_PROTECT_DEL(buf, len, (ROBIN_PROTECT_DEL *)hdr, &plen);
					if (ret != ROBIN_SUCCESS) {
						free(hdr);
						hdr = NULL;
						plen = 0;
					}
				}
				break;


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
		case ROBIN_MSG_PONG:
			if (hlen < sizeof(ROBIN_PONG)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_PONG));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUS:
			if (hlen < sizeof(ROBIN_STATUS)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUS));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSHDL:
			if (hlen < sizeof(ROBIN_STATUSHDL)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSHDL));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSHDLSUM:
			if (hlen < sizeof(ROBIN_STATUSHDLSUM)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSHDLSUM));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSROUTE:
			if (hlen < sizeof(ROBIN_STATUSROUTE)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSROUTE));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSLOCK:
			if (hlen < sizeof(ROBIN_STATUSLOCK)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSLOCK));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSINFO:
			if (hlen < sizeof(ROBIN_STATUSINFO)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSINFO));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSACL:
			if (hlen < sizeof(ROBIN_STATUSACL)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSACL));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSDATA:
			if (hlen < sizeof(ROBIN_STATUSDATA)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSDATA));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSDIRENT:
			if (hlen < sizeof(ROBIN_STATUSDIRENT)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSDIRENT));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSTOKEN:
			if (hlen < sizeof(ROBIN_STATUSTOKEN)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSTOKEN));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSDISK:
			if (hlen < sizeof(ROBIN_STATUSDISK)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSDISK));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSHOST:
			if (hlen < sizeof(ROBIN_STATUSHOST)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSHOST));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSGROUP:
			if (hlen < sizeof(ROBIN_STATUSGROUP)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSGROUP));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSOID:
			if (hlen < sizeof(ROBIN_STATUSOID)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSOID));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSPROTECT:
			if (hlen < sizeof(ROBIN_STATUSPROTECT)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSPROTECT));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_STATUSSYNC:
			if (hlen < sizeof(ROBIN_STATUSSYNC)) {
				log_warnx("==> STATE: status reply misencoded (%zu < %zu)",
						hlen, sizeof(ROBIN_STATUSSYNC));
				goto out;
			}
			ret = robin_state_rescan_rep(context, con,
					(ROBIN_STATUS *)hdr, &statematch);
			break;

		case ROBIN_MSG_GETROOT:
		case ROBIN_MSG_GETROUTE:
		case ROBIN_MSG_GETDISK:
		case ROBIN_MSG_GETCLIENT:
		case ROBIN_MSG_GETOID:
		case ROBIN_MSG_SETOID:
		case ROBIN_MSG_GETLOCK:
		case ROBIN_MSG_GETACTION:
		case ROBIN_MSG_GETTRANS:
		case ROBIN_MSG_PING:
		case ROBIN_MSG_SETCLIENTID:
		case ROBIN_MSG_SETCON:
		case ROBIN_MSG_DISCONNECT:
		case ROBIN_MSG_REFRESH:
		case ROBIN_MSG_MKNODE:
		case ROBIN_MSG_MKSYM:
		case ROBIN_MSG_OPEN:
		case ROBIN_MSG_UNLOCK:
		case ROBIN_MSG_GETATTR:
		case ROBIN_MSG_PUTATTR:
		case ROBIN_MSG_GETACL:
		case ROBIN_MSG_PUTACL:
		case ROBIN_MSG_READ:
		case ROBIN_MSG_WRITE:
		case ROBIN_MSG_APPEND:
		case ROBIN_MSG_TRANS_START:
		case ROBIN_MSG_TRANS_WRITE:
		case ROBIN_MSG_TRANS_APPEND:
		case ROBIN_MSG_TRANS_READ:
		case ROBIN_MSG_TRANS_FINISH:
		case ROBIN_MSG_TRANS_ABORT:
		case ROBIN_MSG_TRANS_SYNC:
		case ROBIN_MSG_NODE_PUT:
		case ROBIN_MSG_NODE_DEL:
		case ROBIN_MSG_NODE_COW:
		case ROBIN_MSG_NODE_SYNC:
		case ROBIN_MSG_NODE_XFER:
		case ROBIN_MSG_NODE_SNAP:
		case ROBIN_MSG_NODE_GETSUM:
		case ROBIN_MSG_LOOKUP:
		case ROBIN_MSG_READDIR:
		case ROBIN_MSG_DIRLINK:
		case ROBIN_MSG_DIRUNLINK:
		case ROBIN_MSG_DIRRELINK:
		case ROBIN_MSG_DIRCREATE:
		case ROBIN_MSG_DIRSYMLINK:
		case ROBIN_MSG_DIRRENAME:
		case ROBIN_MSG_DIRHISTGET:
		case ROBIN_MSG_DIRHISTSET:
		case ROBIN_MSG_GROUP_CREATE:
		case ROBIN_MSG_GROUP_DELETE:
		case ROBIN_MSG_GROUP_MODIFY:
		case ROBIN_MSG_GROUP_RENAME:
		case ROBIN_MSG_GROUP_ADD:
		case ROBIN_MSG_GROUP_DEL:
		case ROBIN_MSG_GROUP_GET:
		case ROBIN_MSG_GROUP_PUT:
		case ROBIN_MSG_GROUP_EVAL:
		case ROBIN_MSG_IHAVE_PART:
		case ROBIN_MSG_IHAVE_VOLUME:
		case ROBIN_MSG_IHAVE_NODE:
		case ROBIN_MSG_IHAVE_ROUTE:
		case ROBIN_MSG_IHAVE_FINISHED:
		case ROBIN_MSG_IHAVE_GROUP:
		case ROBIN_MSG_IHAVE_TRANS:
		case ROBIN_MSG_IHAVE_WITHDRAW:
		case ROBIN_MSG_IHAVE_PROTECT:
		case ROBIN_MSG_VOLUME_GETROOT:
		case ROBIN_MSG_VOLUME_SETROOT:
		case ROBIN_MSG_VOLUME_CREATE:
		case ROBIN_MSG_VOLUME_MKNODE:
		case ROBIN_MSG_VOLUME_CHNODE:
		case ROBIN_MSG_VOLUME_STNODE:
		case ROBIN_MSG_VOLUME_RMNODE:
		case ROBIN_MSG_VOLUME_SNAPSHOT:
		case ROBIN_MSG_VOLUME_DIRLINK:
		case ROBIN_MSG_VOLUME_DIRUNLINK:
		case ROBIN_MSG_VOLUME_VRNODE:
		case ROBIN_MSG_VOLUME_VRSIZE:
		case ROBIN_MSG_VOLUME_RACL:
		case ROBIN_MSG_VOLUME_WACL:
		case ROBIN_MSG_TOKEN_VERIFY:
		case ROBIN_MSG_TOKEN_PUT:
		case ROBIN_MSG_TOKEN_GET:
		case ROBIN_MSG_TOKEN_DEL:
		case ROBIN_MSG_COMPOUND:
		case ROBIN_MSG_DISK_INITIALIZE:
		case ROBIN_MSG_DISK_MODIFY:
		case ROBIN_MSG_DISK_RECOVER:
		case ROBIN_MSG_DISK_BALANCE:
		case ROBIN_MSG_DISK_POWERUP:
		case ROBIN_MSG_DISK_POWERDOWN:
		case ROBIN_MSG_PROTECT_GET:
		case ROBIN_MSG_PROTECT_ADD:
		case ROBIN_MSG_PROTECT_DEL:
			break;

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
		case ROBIN_MSG_GETROOT:
			if (len != sizeof(ROBIN_GETROOT))
				goto out;
			free_ROBIN_GETROOT((ROBIN_GETROOT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETROUTE:
			if (len != sizeof(ROBIN_GETROUTE))
				goto out;
			free_ROBIN_GETROUTE((ROBIN_GETROUTE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETDISK:
			if (len != sizeof(ROBIN_GETDISK))
				goto out;
			free_ROBIN_GETDISK((ROBIN_GETDISK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETCLIENT:
			if (len != sizeof(ROBIN_GETCLIENT))
				goto out;
			free_ROBIN_GETCLIENT((ROBIN_GETCLIENT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETOID:
			if (len != sizeof(ROBIN_GETOID))
				goto out;
			free_ROBIN_GETOID((ROBIN_GETOID *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_SETOID:
			if (len != sizeof(ROBIN_SETOID))
				goto out;
			free_ROBIN_SETOID((ROBIN_SETOID *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETLOCK:
			if (len != sizeof(ROBIN_GETLOCK))
				goto out;
			free_ROBIN_GETLOCK((ROBIN_GETLOCK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETACTION:
			if (len != sizeof(ROBIN_GETACTION))
				goto out;
			free_ROBIN_GETACTION((ROBIN_GETACTION *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETTRANS:
			if (len != sizeof(ROBIN_GETTRANS))
				goto out;
			free_ROBIN_GETTRANS((ROBIN_GETTRANS *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PING:
			if (len != sizeof(ROBIN_PING))
				goto out;
			free_ROBIN_PING((ROBIN_PING *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PONG:
			if (len != sizeof(ROBIN_PONG))
				goto out;
			free_ROBIN_PONG((ROBIN_PONG *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_SETCLIENTID:
			if (len != sizeof(ROBIN_SETCLIENTID))
				goto out;
			free_ROBIN_SETCLIENTID((ROBIN_SETCLIENTID *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_SETCON:
			if (len != sizeof(ROBIN_SETCON))
				goto out;
			free_ROBIN_SETCON((ROBIN_SETCON *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISCONNECT:
			if (len != sizeof(ROBIN_DISCONNECT))
				goto out;
			free_ROBIN_DISCONNECT((ROBIN_DISCONNECT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_REFRESH:
			if (len != sizeof(ROBIN_REFRESH))
				goto out;
			free_ROBIN_REFRESH((ROBIN_REFRESH *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUS:
			if (len != sizeof(ROBIN_STATUS))
				goto out;
			free_ROBIN_STATUS((ROBIN_STATUS *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSHDL:
			if (len != sizeof(ROBIN_STATUSHDL))
				goto out;
			free_ROBIN_STATUSHDL((ROBIN_STATUSHDL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSHDLSUM:
			if (len != sizeof(ROBIN_STATUSHDLSUM))
				goto out;
			free_ROBIN_STATUSHDLSUM((ROBIN_STATUSHDLSUM *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSROUTE:
			if (len != sizeof(ROBIN_STATUSROUTE))
				goto out;
			free_ROBIN_STATUSROUTE((ROBIN_STATUSROUTE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSLOCK:
			if (len != sizeof(ROBIN_STATUSLOCK))
				goto out;
			free_ROBIN_STATUSLOCK((ROBIN_STATUSLOCK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSINFO:
			if (len != sizeof(ROBIN_STATUSINFO))
				goto out;
			free_ROBIN_STATUSINFO((ROBIN_STATUSINFO *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSACL:
			if (len != sizeof(ROBIN_STATUSACL))
				goto out;
			free_ROBIN_STATUSACL((ROBIN_STATUSACL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSDATA:
			if (len != sizeof(ROBIN_STATUSDATA))
				goto out;
			free_ROBIN_STATUSDATA((ROBIN_STATUSDATA *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSDIRENT:
			if (len != sizeof(ROBIN_STATUSDIRENT))
				goto out;
			free_ROBIN_STATUSDIRENT((ROBIN_STATUSDIRENT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSTOKEN:
			if (len != sizeof(ROBIN_STATUSTOKEN))
				goto out;
			free_ROBIN_STATUSTOKEN((ROBIN_STATUSTOKEN *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSDISK:
			if (len != sizeof(ROBIN_STATUSDISK))
				goto out;
			free_ROBIN_STATUSDISK((ROBIN_STATUSDISK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSHOST:
			if (len != sizeof(ROBIN_STATUSHOST))
				goto out;
			free_ROBIN_STATUSHOST((ROBIN_STATUSHOST *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSGROUP:
			if (len != sizeof(ROBIN_STATUSGROUP))
				goto out;
			free_ROBIN_STATUSGROUP((ROBIN_STATUSGROUP *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSOID:
			if (len != sizeof(ROBIN_STATUSOID))
				goto out;
			free_ROBIN_STATUSOID((ROBIN_STATUSOID *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSPROTECT:
			if (len != sizeof(ROBIN_STATUSPROTECT))
				goto out;
			free_ROBIN_STATUSPROTECT((ROBIN_STATUSPROTECT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_STATUSSYNC:
			if (len != sizeof(ROBIN_STATUSSYNC))
				goto out;
			free_ROBIN_STATUSSYNC((ROBIN_STATUSSYNC *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_MKNODE:
			if (len != sizeof(ROBIN_MKNODE))
				goto out;
			free_ROBIN_MKNODE((ROBIN_MKNODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_MKSYM:
			if (len != sizeof(ROBIN_MKSYM))
				goto out;
			free_ROBIN_MKSYM((ROBIN_MKSYM *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_OPEN:
			if (len != sizeof(ROBIN_OPEN))
				goto out;
			free_ROBIN_OPEN((ROBIN_OPEN *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_UNLOCK:
			if (len != sizeof(ROBIN_UNLOCK))
				goto out;
			free_ROBIN_UNLOCK((ROBIN_UNLOCK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETATTR:
			if (len != sizeof(ROBIN_GETATTR))
				goto out;
			free_ROBIN_GETATTR((ROBIN_GETATTR *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PUTATTR:
			if (len != sizeof(ROBIN_PUTATTR))
				goto out;
			free_ROBIN_PUTATTR((ROBIN_PUTATTR *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GETACL:
			if (len != sizeof(ROBIN_GETACL))
				goto out;
			free_ROBIN_GETACL((ROBIN_GETACL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PUTACL:
			if (len != sizeof(ROBIN_PUTACL))
				goto out;
			free_ROBIN_PUTACL((ROBIN_PUTACL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_READ:
			if (len != sizeof(ROBIN_READ))
				goto out;
			free_ROBIN_READ((ROBIN_READ *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_WRITE:
			if (len != sizeof(ROBIN_WRITE))
				goto out;
			free_ROBIN_WRITE((ROBIN_WRITE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_APPEND:
			if (len != sizeof(ROBIN_APPEND))
				goto out;
			free_ROBIN_APPEND((ROBIN_APPEND *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_START:
			if (len != sizeof(ROBIN_TRANS_START))
				goto out;
			free_ROBIN_TRANS_START((ROBIN_TRANS_START *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_WRITE:
			if (len != sizeof(ROBIN_TRANS_WRITE))
				goto out;
			free_ROBIN_TRANS_WRITE((ROBIN_TRANS_WRITE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_APPEND:
			if (len != sizeof(ROBIN_TRANS_APPEND))
				goto out;
			free_ROBIN_TRANS_APPEND((ROBIN_TRANS_APPEND *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_READ:
			if (len != sizeof(ROBIN_TRANS_READ))
				goto out;
			free_ROBIN_TRANS_READ((ROBIN_TRANS_READ *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_FINISH:
			if (len != sizeof(ROBIN_TRANS_FINISH))
				goto out;
			free_ROBIN_TRANS_FINISH((ROBIN_TRANS_FINISH *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_ABORT:
			if (len != sizeof(ROBIN_TRANS_ABORT))
				goto out;
			free_ROBIN_TRANS_ABORT((ROBIN_TRANS_ABORT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TRANS_SYNC:
			if (len != sizeof(ROBIN_TRANS_SYNC))
				goto out;
			free_ROBIN_TRANS_SYNC((ROBIN_TRANS_SYNC *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_PUT:
			if (len != sizeof(ROBIN_NODE_PUT))
				goto out;
			free_ROBIN_NODE_PUT((ROBIN_NODE_PUT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_DEL:
			if (len != sizeof(ROBIN_NODE_DEL))
				goto out;
			free_ROBIN_NODE_DEL((ROBIN_NODE_DEL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_COW:
			if (len != sizeof(ROBIN_NODE_COW))
				goto out;
			free_ROBIN_NODE_COW((ROBIN_NODE_COW *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_SYNC:
			if (len != sizeof(ROBIN_NODE_SYNC))
				goto out;
			free_ROBIN_NODE_SYNC((ROBIN_NODE_SYNC *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_XFER:
			if (len != sizeof(ROBIN_NODE_XFER))
				goto out;
			free_ROBIN_NODE_XFER((ROBIN_NODE_XFER *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_SNAP:
			if (len != sizeof(ROBIN_NODE_SNAP))
				goto out;
			free_ROBIN_NODE_SNAP((ROBIN_NODE_SNAP *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_NODE_GETSUM:
			if (len != sizeof(ROBIN_NODE_GETSUM))
				goto out;
			free_ROBIN_NODE_GETSUM((ROBIN_NODE_GETSUM *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_LOOKUP:
			if (len != sizeof(ROBIN_LOOKUP))
				goto out;
			free_ROBIN_LOOKUP((ROBIN_LOOKUP *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_READDIR:
			if (len != sizeof(ROBIN_READDIR))
				goto out;
			free_ROBIN_READDIR((ROBIN_READDIR *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRLINK:
			if (len != sizeof(ROBIN_DIRLINK))
				goto out;
			free_ROBIN_DIRLINK((ROBIN_DIRLINK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRUNLINK:
			if (len != sizeof(ROBIN_DIRUNLINK))
				goto out;
			free_ROBIN_DIRUNLINK((ROBIN_DIRUNLINK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRRELINK:
			if (len != sizeof(ROBIN_DIRRELINK))
				goto out;
			free_ROBIN_DIRRELINK((ROBIN_DIRRELINK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRCREATE:
			if (len != sizeof(ROBIN_DIRCREATE))
				goto out;
			free_ROBIN_DIRCREATE((ROBIN_DIRCREATE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRSYMLINK:
			if (len != sizeof(ROBIN_DIRSYMLINK))
				goto out;
			free_ROBIN_DIRSYMLINK((ROBIN_DIRSYMLINK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRRENAME:
			if (len != sizeof(ROBIN_DIRRENAME))
				goto out;
			free_ROBIN_DIRRENAME((ROBIN_DIRRENAME *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRHISTGET:
			if (len != sizeof(ROBIN_DIRHISTGET))
				goto out;
			free_ROBIN_DIRHISTGET((ROBIN_DIRHISTGET *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DIRHISTSET:
			if (len != sizeof(ROBIN_DIRHISTSET))
				goto out;
			free_ROBIN_DIRHISTSET((ROBIN_DIRHISTSET *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_CREATE:
			if (len != sizeof(ROBIN_GROUP_CREATE))
				goto out;
			free_ROBIN_GROUP_CREATE((ROBIN_GROUP_CREATE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_DELETE:
			if (len != sizeof(ROBIN_GROUP_DELETE))
				goto out;
			free_ROBIN_GROUP_DELETE((ROBIN_GROUP_DELETE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_MODIFY:
			if (len != sizeof(ROBIN_GROUP_MODIFY))
				goto out;
			free_ROBIN_GROUP_MODIFY((ROBIN_GROUP_MODIFY *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_RENAME:
			if (len != sizeof(ROBIN_GROUP_RENAME))
				goto out;
			free_ROBIN_GROUP_RENAME((ROBIN_GROUP_RENAME *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_ADD:
			if (len != sizeof(ROBIN_GROUP_ADD))
				goto out;
			free_ROBIN_GROUP_ADD((ROBIN_GROUP_ADD *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_DEL:
			if (len != sizeof(ROBIN_GROUP_DEL))
				goto out;
			free_ROBIN_GROUP_DEL((ROBIN_GROUP_DEL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_GET:
			if (len != sizeof(ROBIN_GROUP_GET))
				goto out;
			free_ROBIN_GROUP_GET((ROBIN_GROUP_GET *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_PUT:
			if (len != sizeof(ROBIN_GROUP_PUT))
				goto out;
			free_ROBIN_GROUP_PUT((ROBIN_GROUP_PUT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_GROUP_EVAL:
			if (len != sizeof(ROBIN_GROUP_EVAL))
				goto out;
			free_ROBIN_GROUP_EVAL((ROBIN_GROUP_EVAL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_PART:
			if (len != sizeof(ROBIN_IHAVE_PART))
				goto out;
			free_ROBIN_IHAVE_PART((ROBIN_IHAVE_PART *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_VOLUME:
			if (len != sizeof(ROBIN_IHAVE_VOLUME))
				goto out;
			free_ROBIN_IHAVE_VOLUME((ROBIN_IHAVE_VOLUME *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_NODE:
			if (len != sizeof(ROBIN_IHAVE_NODE))
				goto out;
			free_ROBIN_IHAVE_NODE((ROBIN_IHAVE_NODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_ROUTE:
			if (len != sizeof(ROBIN_IHAVE_ROUTE))
				goto out;
			free_ROBIN_IHAVE_ROUTE((ROBIN_IHAVE_ROUTE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_FINISHED:
			if (len != sizeof(ROBIN_IHAVE_FINISHED))
				goto out;
			free_ROBIN_IHAVE_FINISHED((ROBIN_IHAVE_FINISHED *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_GROUP:
			if (len != sizeof(ROBIN_IHAVE_GROUP))
				goto out;
			free_ROBIN_IHAVE_GROUP((ROBIN_IHAVE_GROUP *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_TRANS:
			if (len != sizeof(ROBIN_IHAVE_TRANS))
				goto out;
			free_ROBIN_IHAVE_TRANS((ROBIN_IHAVE_TRANS *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_WITHDRAW:
			if (len != sizeof(ROBIN_IHAVE_WITHDRAW))
				goto out;
			free_ROBIN_IHAVE_WITHDRAW((ROBIN_IHAVE_WITHDRAW *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_IHAVE_PROTECT:
			if (len != sizeof(ROBIN_IHAVE_PROTECT))
				goto out;
			free_ROBIN_IHAVE_PROTECT((ROBIN_IHAVE_PROTECT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_GETROOT:
			if (len != sizeof(ROBIN_VOLUME_GETROOT))
				goto out;
			free_ROBIN_VOLUME_GETROOT((ROBIN_VOLUME_GETROOT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_SETROOT:
			if (len != sizeof(ROBIN_VOLUME_SETROOT))
				goto out;
			free_ROBIN_VOLUME_SETROOT((ROBIN_VOLUME_SETROOT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_CREATE:
			if (len != sizeof(ROBIN_VOLUME_CREATE))
				goto out;
			free_ROBIN_VOLUME_CREATE((ROBIN_VOLUME_CREATE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_MKNODE:
			if (len != sizeof(ROBIN_VOLUME_MKNODE))
				goto out;
			free_ROBIN_VOLUME_MKNODE((ROBIN_VOLUME_MKNODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_CHNODE:
			if (len != sizeof(ROBIN_VOLUME_CHNODE))
				goto out;
			free_ROBIN_VOLUME_CHNODE((ROBIN_VOLUME_CHNODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_STNODE:
			if (len != sizeof(ROBIN_VOLUME_STNODE))
				goto out;
			free_ROBIN_VOLUME_STNODE((ROBIN_VOLUME_STNODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_RMNODE:
			if (len != sizeof(ROBIN_VOLUME_RMNODE))
				goto out;
			free_ROBIN_VOLUME_RMNODE((ROBIN_VOLUME_RMNODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_SNAPSHOT:
			if (len != sizeof(ROBIN_VOLUME_SNAPSHOT))
				goto out;
			free_ROBIN_VOLUME_SNAPSHOT((ROBIN_VOLUME_SNAPSHOT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_DIRLINK:
			if (len != sizeof(ROBIN_VOLUME_DIRLINK))
				goto out;
			free_ROBIN_VOLUME_DIRLINK((ROBIN_VOLUME_DIRLINK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_DIRUNLINK:
			if (len != sizeof(ROBIN_VOLUME_DIRUNLINK))
				goto out;
			free_ROBIN_VOLUME_DIRUNLINK((ROBIN_VOLUME_DIRUNLINK *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_VRNODE:
			if (len != sizeof(ROBIN_VOLUME_VRNODE))
				goto out;
			free_ROBIN_VOLUME_VRNODE((ROBIN_VOLUME_VRNODE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_VRSIZE:
			if (len != sizeof(ROBIN_VOLUME_VRSIZE))
				goto out;
			free_ROBIN_VOLUME_VRSIZE((ROBIN_VOLUME_VRSIZE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_RACL:
			if (len != sizeof(ROBIN_VOLUME_RACL))
				goto out;
			free_ROBIN_VOLUME_RACL((ROBIN_VOLUME_RACL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_VOLUME_WACL:
			if (len != sizeof(ROBIN_VOLUME_WACL))
				goto out;
			free_ROBIN_VOLUME_WACL((ROBIN_VOLUME_WACL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TOKEN_VERIFY:
			if (len != sizeof(ROBIN_TOKEN_VERIFY))
				goto out;
			free_ROBIN_TOKEN_VERIFY((ROBIN_TOKEN_VERIFY *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TOKEN_PUT:
			if (len != sizeof(ROBIN_TOKEN_PUT))
				goto out;
			free_ROBIN_TOKEN_PUT((ROBIN_TOKEN_PUT *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TOKEN_GET:
			if (len != sizeof(ROBIN_TOKEN_GET))
				goto out;
			free_ROBIN_TOKEN_GET((ROBIN_TOKEN_GET *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_TOKEN_DEL:
			if (len != sizeof(ROBIN_TOKEN_DEL))
				goto out;
			free_ROBIN_TOKEN_DEL((ROBIN_TOKEN_DEL *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_COMPOUND:
			if (len != sizeof(ROBIN_COMPOUND))
				goto out;
			free_ROBIN_COMPOUND((ROBIN_COMPOUND *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISK_INITIALIZE:
			if (len != sizeof(ROBIN_DISK_INITIALIZE))
				goto out;
			free_ROBIN_DISK_INITIALIZE((ROBIN_DISK_INITIALIZE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISK_MODIFY:
			if (len != sizeof(ROBIN_DISK_MODIFY))
				goto out;
			free_ROBIN_DISK_MODIFY((ROBIN_DISK_MODIFY *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISK_RECOVER:
			if (len != sizeof(ROBIN_DISK_RECOVER))
				goto out;
			free_ROBIN_DISK_RECOVER((ROBIN_DISK_RECOVER *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISK_BALANCE:
			if (len != sizeof(ROBIN_DISK_BALANCE))
				goto out;
			free_ROBIN_DISK_BALANCE((ROBIN_DISK_BALANCE *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISK_POWERUP:
			if (len != sizeof(ROBIN_DISK_POWERUP))
				goto out;
			free_ROBIN_DISK_POWERUP((ROBIN_DISK_POWERUP *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_DISK_POWERDOWN:
			if (len != sizeof(ROBIN_DISK_POWERDOWN))
				goto out;
			free_ROBIN_DISK_POWERDOWN((ROBIN_DISK_POWERDOWN *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PROTECT_GET:
			if (len != sizeof(ROBIN_PROTECT_GET))
				goto out;
			free_ROBIN_PROTECT_GET((ROBIN_PROTECT_GET *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PROTECT_ADD:
			if (len != sizeof(ROBIN_PROTECT_ADD))
				goto out;
			free_ROBIN_PROTECT_ADD((ROBIN_PROTECT_ADD *)hdr);
			free(hdr);
			break;

		case ROBIN_MSG_PROTECT_DEL:
			if (len != sizeof(ROBIN_PROTECT_DEL))
				goto out;
			free_ROBIN_PROTECT_DEL((ROBIN_PROTECT_DEL *)hdr);
			free(hdr);
			break;

	}
	return;

out:
	log_warnx("robin_api_state_free_msg: MISMATCHED FREE!  type=%d len=%zu",
			type, len);
}

int
robin_api_send_getroot(robin_context context, robin_con con, ROBIN_GETROOT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETROOT, buf, buflen, msg, &len, ret);
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
robin_api_send_getroute(robin_context context, robin_con con, ROBIN_GETROUTE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETROUTE, buf, buflen, msg, &len, ret);
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
robin_api_send_getdisk(robin_context context, robin_con con, ROBIN_GETDISK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETDISK, buf, buflen, msg, &len, ret);
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
robin_api_send_getclient(robin_context context, robin_con con, ROBIN_GETCLIENT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETCLIENT, buf, buflen, msg, &len, ret);
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
robin_api_send_getoid(robin_context context, robin_con con, ROBIN_GETOID *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETOID, buf, buflen, msg, &len, ret);
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
robin_api_send_setoid(robin_context context, robin_con con, ROBIN_SETOID *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_SETOID, buf, buflen, msg, &len, ret);
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
robin_api_send_getlock(robin_context context, robin_con con, ROBIN_GETLOCK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETLOCK, buf, buflen, msg, &len, ret);
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
robin_api_send_getaction(robin_context context, robin_con con, ROBIN_GETACTION *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETACTION, buf, buflen, msg, &len, ret);
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
robin_api_send_gettrans(robin_context context, robin_con con, ROBIN_GETTRANS *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETTRANS, buf, buflen, msg, &len, ret);
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
robin_api_send_setclientid(robin_context context, robin_con con, ROBIN_SETCLIENTID *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_SETCLIENTID, buf, buflen, msg, &len, ret);
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
robin_api_send_setcon(robin_context context, robin_con con, ROBIN_SETCON *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_SETCON, buf, buflen, msg, &len, ret);
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
robin_api_send_disconnect(robin_context context, robin_con con, ROBIN_DISCONNECT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISCONNECT, buf, buflen, msg, &len, ret);
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
robin_api_send_refresh(robin_context context, robin_con con, ROBIN_REFRESH *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_REFRESH, buf, buflen, msg, &len, ret);
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
robin_api_send_status(robin_context context, robin_con con, ROBIN_STATUS *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUS, buf, buflen, msg, &len, ret);
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
robin_api_send_statushdl(robin_context context, robin_con con, ROBIN_STATUSHDL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSHDL, buf, buflen, msg, &len, ret);
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
robin_api_send_statushdlsum(robin_context context, robin_con con, ROBIN_STATUSHDLSUM *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSHDLSUM, buf, buflen, msg, &len, ret);
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
robin_api_send_statusroute(robin_context context, robin_con con, ROBIN_STATUSROUTE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSROUTE, buf, buflen, msg, &len, ret);
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
robin_api_send_statuslock(robin_context context, robin_con con, ROBIN_STATUSLOCK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSLOCK, buf, buflen, msg, &len, ret);
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
robin_api_send_statusinfo(robin_context context, robin_con con, ROBIN_STATUSINFO *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSINFO, buf, buflen, msg, &len, ret);
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
robin_api_send_statusacl(robin_context context, robin_con con, ROBIN_STATUSACL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSACL, buf, buflen, msg, &len, ret);
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
robin_api_send_statusdata(robin_context context, robin_con con, ROBIN_STATUSDATA *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSDATA, buf, buflen, msg, &len, ret);
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
robin_api_send_statusdirent(robin_context context, robin_con con, ROBIN_STATUSDIRENT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSDIRENT, buf, buflen, msg, &len, ret);
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
robin_api_send_statustoken(robin_context context, robin_con con, ROBIN_STATUSTOKEN *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSTOKEN, buf, buflen, msg, &len, ret);
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
robin_api_send_statusdisk(robin_context context, robin_con con, ROBIN_STATUSDISK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSDISK, buf, buflen, msg, &len, ret);
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
robin_api_send_statushost(robin_context context, robin_con con, ROBIN_STATUSHOST *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSHOST, buf, buflen, msg, &len, ret);
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
robin_api_send_statusgroup(robin_context context, robin_con con, ROBIN_STATUSGROUP *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSGROUP, buf, buflen, msg, &len, ret);
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
robin_api_send_statusoid(robin_context context, robin_con con, ROBIN_STATUSOID *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSOID, buf, buflen, msg, &len, ret);
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
robin_api_send_statusprotect(robin_context context, robin_con con, ROBIN_STATUSPROTECT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSPROTECT, buf, buflen, msg, &len, ret);
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
robin_api_send_statussync(robin_context context, robin_con con, ROBIN_STATUSSYNC *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_STATUSSYNC, buf, buflen, msg, &len, ret);
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
robin_api_send_mknode(robin_context context, robin_con con, ROBIN_MKNODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_MKNODE, buf, buflen, msg, &len, ret);
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
robin_api_send_mksym(robin_context context, robin_con con, ROBIN_MKSYM *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_MKSYM, buf, buflen, msg, &len, ret);
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
robin_api_send_open(robin_context context, robin_con con, ROBIN_OPEN *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_OPEN, buf, buflen, msg, &len, ret);
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
robin_api_send_unlock(robin_context context, robin_con con, ROBIN_UNLOCK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_UNLOCK, buf, buflen, msg, &len, ret);
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
robin_api_send_getattr(robin_context context, robin_con con, ROBIN_GETATTR *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETATTR, buf, buflen, msg, &len, ret);
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
robin_api_send_putattr(robin_context context, robin_con con, ROBIN_PUTATTR *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_PUTATTR, buf, buflen, msg, &len, ret);
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
robin_api_send_getacl(robin_context context, robin_con con, ROBIN_GETACL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GETACL, buf, buflen, msg, &len, ret);
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
robin_api_send_putacl(robin_context context, robin_con con, ROBIN_PUTACL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_PUTACL, buf, buflen, msg, &len, ret);
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
robin_api_send_read(robin_context context, robin_con con, ROBIN_READ *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_READ, buf, buflen, msg, &len, ret);
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
robin_api_send_write(robin_context context, robin_con con, ROBIN_WRITE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_WRITE, buf, buflen, msg, &len, ret);
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
robin_api_send_append(robin_context context, robin_con con, ROBIN_APPEND *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_APPEND, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_start(robin_context context, robin_con con, ROBIN_TRANS_START *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_START, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_write(robin_context context, robin_con con, ROBIN_TRANS_WRITE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_WRITE, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_append(robin_context context, robin_con con, ROBIN_TRANS_APPEND *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_APPEND, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_read(robin_context context, robin_con con, ROBIN_TRANS_READ *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_READ, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_finish(robin_context context, robin_con con, ROBIN_TRANS_FINISH *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_FINISH, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_abort(robin_context context, robin_con con, ROBIN_TRANS_ABORT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_ABORT, buf, buflen, msg, &len, ret);
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
robin_api_send_trans_sync(robin_context context, robin_con con, ROBIN_TRANS_SYNC *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TRANS_SYNC, buf, buflen, msg, &len, ret);
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
robin_api_send_node_put(robin_context context, robin_con con, ROBIN_NODE_PUT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_PUT, buf, buflen, msg, &len, ret);
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
robin_api_send_node_del(robin_context context, robin_con con, ROBIN_NODE_DEL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_DEL, buf, buflen, msg, &len, ret);
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
robin_api_send_node_cow(robin_context context, robin_con con, ROBIN_NODE_COW *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_COW, buf, buflen, msg, &len, ret);
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
robin_api_send_node_sync(robin_context context, robin_con con, ROBIN_NODE_SYNC *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_SYNC, buf, buflen, msg, &len, ret);
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
robin_api_send_node_xfer(robin_context context, robin_con con, ROBIN_NODE_XFER *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_XFER, buf, buflen, msg, &len, ret);
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
robin_api_send_node_snap(robin_context context, robin_con con, ROBIN_NODE_SNAP *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_SNAP, buf, buflen, msg, &len, ret);
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
robin_api_send_node_getsum(robin_context context, robin_con con, ROBIN_NODE_GETSUM *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_NODE_GETSUM, buf, buflen, msg, &len, ret);
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
robin_api_send_lookup(robin_context context, robin_con con, ROBIN_LOOKUP *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_LOOKUP, buf, buflen, msg, &len, ret);
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
robin_api_send_readdir(robin_context context, robin_con con, ROBIN_READDIR *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_READDIR, buf, buflen, msg, &len, ret);
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
robin_api_send_dirlink(robin_context context, robin_con con, ROBIN_DIRLINK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRLINK, buf, buflen, msg, &len, ret);
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
robin_api_send_dirunlink(robin_context context, robin_con con, ROBIN_DIRUNLINK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRUNLINK, buf, buflen, msg, &len, ret);
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
robin_api_send_dirrelink(robin_context context, robin_con con, ROBIN_DIRRELINK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRRELINK, buf, buflen, msg, &len, ret);
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
robin_api_send_dircreate(robin_context context, robin_con con, ROBIN_DIRCREATE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRCREATE, buf, buflen, msg, &len, ret);
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
robin_api_send_dirsymlink(robin_context context, robin_con con, ROBIN_DIRSYMLINK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRSYMLINK, buf, buflen, msg, &len, ret);
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
robin_api_send_dirrename(robin_context context, robin_con con, ROBIN_DIRRENAME *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRRENAME, buf, buflen, msg, &len, ret);
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
robin_api_send_dirhistget(robin_context context, robin_con con, ROBIN_DIRHISTGET *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRHISTGET, buf, buflen, msg, &len, ret);
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
robin_api_send_dirhistset(robin_context context, robin_con con, ROBIN_DIRHISTSET *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DIRHISTSET, buf, buflen, msg, &len, ret);
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
robin_api_send_group_create(robin_context context, robin_con con, ROBIN_GROUP_CREATE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_CREATE, buf, buflen, msg, &len, ret);
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
robin_api_send_group_delete(robin_context context, robin_con con, ROBIN_GROUP_DELETE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_DELETE, buf, buflen, msg, &len, ret);
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
robin_api_send_group_modify(robin_context context, robin_con con, ROBIN_GROUP_MODIFY *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_MODIFY, buf, buflen, msg, &len, ret);
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
robin_api_send_group_rename(robin_context context, robin_con con, ROBIN_GROUP_RENAME *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_RENAME, buf, buflen, msg, &len, ret);
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
robin_api_send_group_add(robin_context context, robin_con con, ROBIN_GROUP_ADD *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_ADD, buf, buflen, msg, &len, ret);
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
robin_api_send_group_del(robin_context context, robin_con con, ROBIN_GROUP_DEL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_DEL, buf, buflen, msg, &len, ret);
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
robin_api_send_group_get(robin_context context, robin_con con, ROBIN_GROUP_GET *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_GET, buf, buflen, msg, &len, ret);
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
robin_api_send_group_put(robin_context context, robin_con con, ROBIN_GROUP_PUT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_PUT, buf, buflen, msg, &len, ret);
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
robin_api_send_group_eval(robin_context context, robin_con con, ROBIN_GROUP_EVAL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_GROUP_EVAL, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_part(robin_context context, robin_con con, ROBIN_IHAVE_PART *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_PART, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_volume(robin_context context, robin_con con, ROBIN_IHAVE_VOLUME *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_VOLUME, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_node(robin_context context, robin_con con, ROBIN_IHAVE_NODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_NODE, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_route(robin_context context, robin_con con, ROBIN_IHAVE_ROUTE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_ROUTE, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_finished(robin_context context, robin_con con, ROBIN_IHAVE_FINISHED *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_FINISHED, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_group(robin_context context, robin_con con, ROBIN_IHAVE_GROUP *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_GROUP, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_trans(robin_context context, robin_con con, ROBIN_IHAVE_TRANS *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_TRANS, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_withdraw(robin_context context, robin_con con, ROBIN_IHAVE_WITHDRAW *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_WITHDRAW, buf, buflen, msg, &len, ret);
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
robin_api_send_ihave_protect(robin_context context, robin_con con, ROBIN_IHAVE_PROTECT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_IHAVE_PROTECT, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_getroot(robin_context context, robin_con con, ROBIN_VOLUME_GETROOT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_GETROOT, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_setroot(robin_context context, robin_con con, ROBIN_VOLUME_SETROOT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_SETROOT, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_create(robin_context context, robin_con con, ROBIN_VOLUME_CREATE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_CREATE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_mknode(robin_context context, robin_con con, ROBIN_VOLUME_MKNODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_MKNODE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_chnode(robin_context context, robin_con con, ROBIN_VOLUME_CHNODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_CHNODE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_stnode(robin_context context, robin_con con, ROBIN_VOLUME_STNODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_STNODE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_rmnode(robin_context context, robin_con con, ROBIN_VOLUME_RMNODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_RMNODE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_snapshot(robin_context context, robin_con con, ROBIN_VOLUME_SNAPSHOT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_SNAPSHOT, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_dirlink(robin_context context, robin_con con, ROBIN_VOLUME_DIRLINK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_DIRLINK, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_dirunlink(robin_context context, robin_con con, ROBIN_VOLUME_DIRUNLINK *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_DIRUNLINK, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_vrnode(robin_context context, robin_con con, ROBIN_VOLUME_VRNODE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_VRNODE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_vrsize(robin_context context, robin_con con, ROBIN_VOLUME_VRSIZE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_VRSIZE, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_racl(robin_context context, robin_con con, ROBIN_VOLUME_RACL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_RACL, buf, buflen, msg, &len, ret);
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
robin_api_send_volume_wacl(robin_context context, robin_con con, ROBIN_VOLUME_WACL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_VOLUME_WACL, buf, buflen, msg, &len, ret);
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
robin_api_send_token_verify(robin_context context, robin_con con, ROBIN_TOKEN_VERIFY *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TOKEN_VERIFY, buf, buflen, msg, &len, ret);
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
robin_api_send_token_put(robin_context context, robin_con con, ROBIN_TOKEN_PUT *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TOKEN_PUT, buf, buflen, msg, &len, ret);
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
robin_api_send_token_get(robin_context context, robin_con con, ROBIN_TOKEN_GET *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TOKEN_GET, buf, buflen, msg, &len, ret);
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
robin_api_send_token_del(robin_context context, robin_con con, ROBIN_TOKEN_DEL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_TOKEN_DEL, buf, buflen, msg, &len, ret);
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
robin_api_send_compound(robin_context context, robin_con con, ROBIN_COMPOUND *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_COMPOUND, buf, buflen, msg, &len, ret);
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
robin_api_send_disk_initialize(robin_context context, robin_con con, ROBIN_DISK_INITIALIZE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISK_INITIALIZE, buf, buflen, msg, &len, ret);
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
robin_api_send_disk_modify(robin_context context, robin_con con, ROBIN_DISK_MODIFY *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISK_MODIFY, buf, buflen, msg, &len, ret);
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
robin_api_send_disk_recover(robin_context context, robin_con con, ROBIN_DISK_RECOVER *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISK_RECOVER, buf, buflen, msg, &len, ret);
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
robin_api_send_disk_balance(robin_context context, robin_con con, ROBIN_DISK_BALANCE *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISK_BALANCE, buf, buflen, msg, &len, ret);
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
robin_api_send_disk_powerup(robin_context context, robin_con con, ROBIN_DISK_POWERUP *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISK_POWERUP, buf, buflen, msg, &len, ret);
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
robin_api_send_disk_powerdown(robin_context context, robin_con con, ROBIN_DISK_POWERDOWN *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_DISK_POWERDOWN, buf, buflen, msg, &len, ret);
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
robin_api_send_protect_get(robin_context context, robin_con con, ROBIN_PROTECT_GET *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_PROTECT_GET, buf, buflen, msg, &len, ret);
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
robin_api_send_protect_add(robin_context context, robin_con con, ROBIN_PROTECT_ADD *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_PROTECT_ADD, buf, buflen, msg, &len, ret);
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
robin_api_send_protect_del(robin_context context, robin_con con, ROBIN_PROTECT_DEL *msg, uint32_t *xid)
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
	TBASN1_MALLOC_ENCODE(ROBIN_PROTECT_DEL, buf, buflen, msg, &len, ret);
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

