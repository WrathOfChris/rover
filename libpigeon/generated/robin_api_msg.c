/* $Gateweaver$ */
/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "robin_locl.h"

int
robin_getroot_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETROOT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_GETROOT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETROOT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getroot,
			ROBIN_MSG_GETROOT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_GETROOT(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getroute_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETROUTE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		int32_t limit	/* int32_t */)
{
	struct robin_state *rs;
	ROBIN_GETROUTE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETROUTE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getroute,
			ROBIN_MSG_GETROUTE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_GETROUTE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->prefix = prefix;
	msg->limit = limit;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getdisk_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETDISK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisks *disks	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_GETDISK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETDISK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getdisk,
			ROBIN_MSG_GETDISK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disks) {
		if ((msg->disks = calloc(1, sizeof(*msg->disks))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisks(disks, msg->disks)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getclient_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETCLIENT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisks *disks	/* SEQUENCEOF */,
		const RobinPrincipals *principals	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_GETCLIENT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETCLIENT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getclient,
			ROBIN_MSG_GETCLIENT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disks) {
		if ((msg->disks = calloc(1, sizeof(*msg->disks))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisks(disks, msg->disks)))
			goto fail;
	}
	if (principals) {
		if ((msg->principals = calloc(1, sizeof(*msg->principals))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipals(principals, msg->principals)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getoid_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETOID *callback, void *arg,
		const RobinPrincipal *proxyuser,
		tb_oid oid	/* OID */)
{
	struct robin_state *rs;
	ROBIN_GETOID *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETOID))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getoid,
			ROBIN_MSG_GETOID, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	msg->oid = oid;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_setoid_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_SETOID *callback, void *arg,
		const RobinPrincipal *proxyuser,
		tb_oid oid	/* OID */)
{
	struct robin_state *rs;
	ROBIN_SETOID *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_SETOID))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_setoid,
			ROBIN_MSG_SETOID, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	msg->oid = oid;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getlock_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETLOCK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GETLOCK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETLOCK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getlock,
			ROBIN_MSG_GETLOCK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_GETLOCK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->prefix = prefix;
	if (principal) {
		if ((msg->principal = calloc(1, sizeof(*msg->principal))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(principal, msg->principal)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getaction_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETACTION *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GETACTION *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETACTION))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getaction,
			ROBIN_MSG_GETACTION, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_GETACTION(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->prefix = prefix;
	if (principal) {
		if ((msg->principal = calloc(1, sizeof(*msg->principal))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(principal, msg->principal)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_gettrans_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETTRANS *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		const RobinPrincipal *principal	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GETTRANS *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETTRANS))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_gettrans,
			ROBIN_MSG_GETTRANS, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_GETTRANS(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->prefix = prefix;
	if (principal) {
		if ((msg->principal = calloc(1, sizeof(*msg->principal))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(principal, msg->principal)))
			goto fail;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ping_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_PING *callback, void *arg,
		const RobinPrincipal *proxyuser)
{
	struct robin_state *rs;
	ROBIN_PING *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PING))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ping,
			ROBIN_MSG_PING, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_pong_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status)
{
	struct robin_state *rs;
	ROBIN_PONG *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PONG))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_pong, ROBIN_MSG_PONG,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;


	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_setclientid_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_SETCLIENTID *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const unsigned char *clientid, size_t clientidlen,
		const unsigned char *identity, size_t identitylen,
		const RobinEncryptionKey *verifier	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_SETCLIENTID *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_SETCLIENTID))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_setclientid,
			ROBIN_MSG_SETCLIENTID, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (clientid == NULL) {
		log_warnx("DEBUG: ROBIN_SETCLIENTID(OCTETSTRING clientid) == NULL");
		abort();
	}
	msg->clientid.length = clientidlen;
	if ((msg->clientid.data = malloc(msg->clientid.length)) == NULL)
		goto fail;
	bcopy(clientid, msg->clientid.data, msg->clientid.length);
	if (identity == NULL) {
		log_warnx("DEBUG: ROBIN_SETCLIENTID(OCTETSTRING identity) == NULL");
		abort();
	}
	msg->identity.length = identitylen;
	if ((msg->identity.data = malloc(msg->identity.length)) == NULL)
		goto fail;
	bcopy(identity, msg->identity.data, msg->identity.length);
	if (verifier == NULL) {
		log_warnx("DEBUG: ROBIN_SETCLIENTID(RobinEncryptionKey verifier) == NULL");
		abort();
	}
	if ((ret = copy_RobinEncryptionKey(verifier, &msg->verifier)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_setcon_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_SETCON *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinConFlags *flags	/* BITSTRING */,
		const RobinHostAddress *addr	/* SEQUENCE */,
		const RobinServerPrefs *prefs	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_SETCON *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_SETCON))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_setcon,
			ROBIN_MSG_SETCON, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_SETCON(RobinConFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinConFlags(flags, &msg->flags)))
		goto fail;
	if (addr) {
		if ((msg->addr = calloc(1, sizeof(*msg->addr))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHostAddress(addr, msg->addr)))
			goto fail;
	}
	if (prefs) {
		if ((msg->prefs = calloc(1, sizeof(*msg->prefs))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinServerPrefs(prefs, msg->prefs)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disconnect_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISCONNECT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinConFlags *flags	/* BITSTRING */,
		const RobinTime *time	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DISCONNECT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISCONNECT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disconnect,
			ROBIN_MSG_DISCONNECT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DISCONNECT(RobinConFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinConFlags(flags, &msg->flags)))
		goto fail;
	if (time == NULL) {
		log_warnx("DEBUG: ROBIN_DISCONNECT(RobinTime time) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(time, &msg->time)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_refresh_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_REFRESH *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_REFRESH *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_REFRESH))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_refresh,
			ROBIN_MSG_REFRESH, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl) {
		if ((msg->hdl = calloc(1, sizeof(*msg->hdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(hdl, msg->hdl)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_status_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status)
{
	struct robin_state *rs;
	ROBIN_STATUS *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUS))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_status, ROBIN_MSG_STATUS,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;


	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statushdl_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinLock *lock	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSHDL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSHDL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statushdl, ROBIN_MSG_STATUSHDL,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSHDL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinLock(lock, msg->lock)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statushdlsum_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinLock *lock	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSHDLSUM *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSHDLSUM))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statushdlsum, ROBIN_MSG_STATUSHDLSUM,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSHDLSUM(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (sum == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSHDLSUM(RobinChecksum sum) == NULL");
		abort();
	}
	if ((ret = copy_RobinChecksum(sum, &msg->sum)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinLock(lock, msg->lock)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusroute_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		ROBIN_ROUTETYPE rtype	/* int32_t */,
		ROBIN_TYPE ntype	/* int32_t */,
		const RobinRouterFlags *flags	/* BITSTRING */,
		int32_t ttl	/* int32_t */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		int64_t size	/* int64_t */,
		const RobinTime *atime	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSROUTE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSROUTE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusroute, ROBIN_MSG_STATUSROUTE,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSROUTE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->prefix = prefix;
	msg->rtype = rtype;
	msg->ntype = ntype;
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSROUTE(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	msg->ttl = ttl;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	msg->size = size;
	if (atime) {
		if ((msg->atime = calloc(1, sizeof(*msg->atime))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinTime(atime, msg->atime)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statuslock_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinLock *lock	/* SEQUENCE */,
		const RobinHosts *hosts	/* SEQUENCEOF */,
		const RobinTokens *tokens	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_STATUSLOCK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSLOCK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statuslock, ROBIN_MSG_STATUSLOCK,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinLock(lock, msg->lock)))
			goto fail;
	}
	if (hosts) {
		if ((msg->hosts = calloc(1, sizeof(*msg->hosts))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHosts(hosts, msg->hosts)))
			goto fail;
	}
	if (tokens) {
		if ((msg->tokens = calloc(1, sizeof(*msg->tokens))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinTokens(tokens, msg->tokens)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusinfo_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinLock *lock	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSINFO *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSINFO))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusinfo, ROBIN_MSG_STATUSINFO,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSINFO(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSINFO(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSINFO(RobinChecksum sum) == NULL");
		abort();
	}
	if ((ret = copy_RobinChecksum(sum, &msg->sum)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinLock(lock, msg->lock)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusacl_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinRightsList *acl	/* SEQUENCEOF */,
		const RobinLock *lock	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSACL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSACL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusacl, ROBIN_MSG_STATUSACL,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (acl == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSACL(RobinRightsList acl) == NULL");
		abort();
	}
	if ((ret = copy_RobinRightsList(acl, &msg->acl)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinLock(lock, msg->lock)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusdata_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const unsigned char *data, size_t datalen)
{
	struct robin_state *rs;
	ROBIN_STATUSDATA *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSDATA))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusdata, ROBIN_MSG_STATUSDATA,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (data == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSDATA(OCTETSTRING data) == NULL");
		abort();
	}
	msg->data.length = datalen;
	if ((msg->data.data = malloc(msg->data.length)) == NULL)
		goto fail;
	bcopy(data, msg->data.data, msg->data.length);

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusdirent_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinDirentries *entries	/* SEQUENCEOF */,
		const RobinLock *lock	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSDIRENT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSDIRENT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusdirent, ROBIN_MSG_STATUSDIRENT,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (entries == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSDIRENT(RobinDirentries entries) == NULL");
		abort();
	}
	if ((ret = copy_RobinDirentries(entries, &msg->entries)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinLock(lock, msg->lock)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statustoken_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSTOKEN *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSTOKEN))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statustoken, ROBIN_MSG_STATUSTOKEN,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSTOKEN(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusdisk_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinDisk *disk	/* SEQUENCE */,
		int64_t usedspace	/* int64_t */,
		int64_t usednodes	/* int64_t */,
		int64_t freespace	/* int64_t */,
		int64_t freenodes	/* int64_t */,
		const RobinTime *rttlatency	/* SEQUENCE */,
		int64_t rbandwidth	/* int64_t */,
		int64_t wbandwidth	/* int64_t */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_STATUSDISK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSDISK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusdisk, ROBIN_MSG_STATUSDISK,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSDISK(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	msg->usedspace = usedspace;
	msg->usednodes = usednodes;
	msg->freespace = freespace;
	msg->freenodes = freenodes;
	if (rttlatency == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSDISK(RobinTime rttlatency) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(rttlatency, &msg->rttlatency)))
		goto fail;
	msg->rbandwidth = rbandwidth;
	msg->wbandwidth = wbandwidth;
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSDISK(RobinDiskFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinDiskFlags(flags, &msg->flags)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statushost_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinHost *host	/* SEQUENCE */,
		const unsigned char *clientid, size_t clientidlen,
		const RobinPrincipals *principals	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_STATUSHOST *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSHOST))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statushost, ROBIN_MSG_STATUSHOST,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (host == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSHOST(RobinHost host) == NULL");
		abort();
	}
	if ((ret = copy_RobinHost(host, &msg->host)))
		goto fail;
	if (clientid == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSHOST(OCTETSTRING clientid) == NULL");
		abort();
	}
	msg->clientid.length = clientidlen;
	if ((msg->clientid.data = malloc(msg->clientid.length)) == NULL)
		goto fail;
	bcopy(clientid, msg->clientid.data, msg->clientid.length);
	if (principals == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSHOST(RobinPrincipals principals) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipals(principals, &msg->principals)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusgroup_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *owner	/* SEQUENCE */,
		const RobinGroupRight *public	/* BITSTRING */,
		const RobinGroupRight *private	/* BITSTRING */,
		const RobinPrincipals *users	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_STATUSGROUP *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSGROUP))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusgroup, ROBIN_MSG_STATUSGROUP,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSGROUP(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (owner) {
		if ((msg->owner = calloc(1, sizeof(*msg->owner))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(owner, msg->owner)))
			goto fail;
	}
	if (public) {
		if ((msg->public = calloc(1, sizeof(*msg->public))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinGroupRight(public, msg->public)))
			goto fail;
	}
	if (private) {
		if ((msg->private = calloc(1, sizeof(*msg->private))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinGroupRight(private, msg->private)))
			goto fail;
	}
	if (users) {
		if ((msg->users = calloc(1, sizeof(*msg->users))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipals(users, msg->users)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusoid_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const unsigned char *data, size_t datalen)
{
	struct robin_state *rs;
	ROBIN_STATUSOID *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSOID))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusoid, ROBIN_MSG_STATUSOID,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (data == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSOID(OCTETSTRING data) == NULL");
		abort();
	}
	msg->data.length = datalen;
	if ((msg->data.data = malloc(msg->data.length)) == NULL)
		goto fail;
	bcopy(data, msg->data.data, msg->data.length);

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statusprotect_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_STATUSPROTECT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSPROTECT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statusprotect, ROBIN_MSG_STATUSPROTECT,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (rules == NULL) {
		log_warnx("DEBUG: ROBIN_STATUSPROTECT(RobinProtectNodes rules) == NULL");
		abort();
	}
	if ((ret = copy_RobinProtectNodes(rules, &msg->rules)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_statussync_reply(robin_context context, robin_con con, uint32_t xid,
		enum rbn_error_number status,
		const RobinSyncChecksum *syncsum	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_STATUSSYNC *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_STATUSSYNC))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_statussync, ROBIN_MSG_STATUSSYNC,
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

	if (syncsum) {
		if ((msg->syncsum = calloc(1, sizeof(*msg->syncsum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinSyncChecksum(syncsum, msg->syncsum)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_mknode_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_MKNODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_MKNODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_MKNODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_mknode,
			ROBIN_MSG_MKNODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_MKNODE(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl) {
		if ((msg->hdl = calloc(1, sizeof(*msg->hdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(hdl, msg->hdl)))
			goto fail;
	}
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_MKNODE(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->lock = *lock;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_mksym_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_MKSYM *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinFilename *dest	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_MKSYM *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_MKSYM))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_mksym,
			ROBIN_MSG_MKSYM, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_MKSYM(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_MKSYM(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_MKSYM(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (dest == NULL) {
		log_warnx("DEBUG: ROBIN_MKSYM(RobinFilename dest) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(dest, &msg->dest)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->lock = *lock;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_open_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_OPEN *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_OPEN *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_OPEN))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_open,
			ROBIN_MSG_OPEN, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_OPEN(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_OPEN(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->lock = *lock;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_unlock_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_UNLOCK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */,
		const RobinTime *expiry	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_UNLOCK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_UNLOCK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_unlock,
			ROBIN_MSG_UNLOCK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_UNLOCK(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_UNLOCK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->lock = *lock;
	}
	if (expiry) {
		if ((msg->expiry = calloc(1, sizeof(*msg->expiry))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinTime(expiry, msg->expiry)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getattr_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETATTR *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GETATTR *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETATTR))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getattr,
			ROBIN_MSG_GETATTR, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_GETATTR(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_GETATTR(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_putattr_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_PUTATTR *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_PUTATTR *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PUTATTR))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_putattr,
			ROBIN_MSG_PUTATTR, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_PUTATTR(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_PUTATTR(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_PUTATTR(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_getacl_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GETACL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GETACL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GETACL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_getacl,
			ROBIN_MSG_GETACL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_GETACL(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_GETACL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (principal) {
		if ((msg->principal = calloc(1, sizeof(*msg->principal))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(principal, msg->principal)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_putacl_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_PUTACL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinRightsList *append	/* SEQUENCEOF */,
		const RobinRightsList *change	/* SEQUENCEOF */,
		const RobinRightsList *delete	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_PUTACL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PUTACL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_putacl,
			ROBIN_MSG_PUTACL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_PUTACL(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_PUTACL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (append) {
		if ((msg->append = calloc(1, sizeof(*msg->append))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinRightsList(append, msg->append)))
			goto fail;
	}
	if (change) {
		if ((msg->change = calloc(1, sizeof(*msg->change))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinRightsList(change, msg->change)))
			goto fail;
	}
	if (delete) {
		if ((msg->delete = calloc(1, sizeof(*msg->delete))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinRightsList(delete, msg->delete)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_read_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_READ *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_READ *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_READ))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_read,
			ROBIN_MSG_READ, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_READ(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->offset = offset;
	msg->length = length;
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_write_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_WRITE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		const unsigned char *data, size_t datalen,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_WRITE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_WRITE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_write,
			ROBIN_MSG_WRITE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_WRITE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->offset = offset;
	msg->length = length;
	if (data == NULL) {
		log_warnx("DEBUG: ROBIN_WRITE(OCTETSTRING data) == NULL");
		abort();
	}
	msg->data.length = datalen;
	if ((msg->data.data = malloc(msg->data.length)) == NULL)
		goto fail;
	bcopy(data, msg->data.data, msg->data.length);
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_append_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_APPEND *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		const unsigned char *data, size_t datalen,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_APPEND *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_APPEND))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_append,
			ROBIN_MSG_APPEND, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_APPEND(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (data == NULL) {
		log_warnx("DEBUG: ROBIN_APPEND(OCTETSTRING data) == NULL");
		abort();
	}
	msg->data.length = datalen;
	if ((msg->data.data = malloc(msg->data.length)) == NULL)
		goto fail;
	bcopy(data, msg->data.data, msg->data.length);
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_start_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_START *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_TRANS_START *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_START))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_start,
			ROBIN_MSG_TRANS_START, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_START(RobinTransFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinTransFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_START(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->offset = offset;
	msg->length = length;
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_write_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_WRITE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinToken *token	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		const unsigned char *data, size_t datalen)
{
	struct robin_state *rs;
	ROBIN_TRANS_WRITE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_WRITE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_write,
			ROBIN_MSG_TRANS_WRITE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_WRITE(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	msg->offset = offset;
	if (data == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_WRITE(OCTETSTRING data) == NULL");
		abort();
	}
	msg->data.length = datalen;
	if ((msg->data.data = malloc(msg->data.length)) == NULL)
		goto fail;
	bcopy(data, msg->data.data, msg->data.length);

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_append_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_APPEND *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinToken *token	/* SEQUENCE */,
		const unsigned char *data, size_t datalen)
{
	struct robin_state *rs;
	ROBIN_TRANS_APPEND *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_APPEND))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_append,
			ROBIN_MSG_TRANS_APPEND, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_APPEND(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	if (data == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_APPEND(OCTETSTRING data) == NULL");
		abort();
	}
	msg->data.length = datalen;
	if ((msg->data.data = malloc(msg->data.length)) == NULL)
		goto fail;
	bcopy(data, msg->data.data, msg->data.length);

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_read_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_READ *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinToken *token	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */)
{
	struct robin_state *rs;
	ROBIN_TRANS_READ *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_READ))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_read,
			ROBIN_MSG_TRANS_READ, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_READ(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	msg->offset = offset;
	msg->length = length;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_finish_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_FINISH *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_TRANS_FINISH *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_FINISH))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_finish,
			ROBIN_MSG_TRANS_FINISH, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_FINISH(RobinTransFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinTransFlags(flags, &msg->flags)))
		goto fail;
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_FINISH(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_abort_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_ABORT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const unsigned char *txid, size_t txidlen)
{
	struct robin_state *rs;
	ROBIN_TRANS_ABORT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_ABORT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_abort,
			ROBIN_MSG_TRANS_ABORT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_ABORT(RobinTransFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinTransFlags(flags, &msg->flags)))
		goto fail;
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_ABORT(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	if (txid) {
		if ((msg->txid = calloc(1, sizeof(*msg->txid))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		msg->txid->length = txidlen;
		if ((msg->txid->data = malloc(msg->txid->length)) == NULL)
			goto fail;
		bcopy(txid, msg->txid->data, msg->txid->length);
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_trans_sync_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TRANS_SYNC *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinSyncFlags *sflags	/* BITSTRING */,
		ROBIN_CKSUMTYPE hardsumtype	/* int32_t */,
		const RobinSyncCommands *cmds	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_TRANS_SYNC *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TRANS_SYNC))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_trans_sync,
			ROBIN_MSG_TRANS_SYNC, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_SYNC(RobinTransFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinTransFlags(flags, &msg->flags)))
		goto fail;
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_SYNC(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	if (sflags == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_SYNC(RobinSyncFlags sflags) == NULL");
		abort();
	}
	if ((ret = copy_RobinSyncFlags(sflags, &msg->sflags)))
		goto fail;
	msg->hardsumtype = hardsumtype;
	if (cmds == NULL) {
		log_warnx("DEBUG: ROBIN_TRANS_SYNC(RobinSyncCommands cmds) == NULL");
		abort();
	}
	if ((ret = copy_RobinSyncCommands(cmds, &msg->cmds)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_put_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_PUT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_TYPE type	/* int32_t */,
		int64_t size	/* int64_t */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_PUT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_PUT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_put,
			ROBIN_MSG_NODE_PUT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_PUT(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_PUT(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->type = type;
	msg->size = size;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_del_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_DEL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_DEL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_DEL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_del,
			ROBIN_MSG_NODE_DEL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_DEL(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_DEL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_cow_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_COW *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinHandle *nhdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_COW *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_COW))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_cow,
			ROBIN_MSG_NODE_COW, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_COW(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_COW(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (nhdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_COW(RobinHandle nhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(nhdl, &msg->nhdl)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_sync_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_SYNC *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_SYNC *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_SYNC))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_sync,
			ROBIN_MSG_NODE_SYNC, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_SYNC(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_SYNC(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_xfer_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_XFER *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_XFER *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_XFER))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_xfer,
			ROBIN_MSG_NODE_XFER, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_XFER(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_XFER(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_snap_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_SNAP *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinHandle *dhdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_SNAP *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_SNAP))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_snap,
			ROBIN_MSG_NODE_SNAP, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_SNAP(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_SNAP(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (dhdl) {
		if ((msg->dhdl = calloc(1, sizeof(*msg->dhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(dhdl, msg->dhdl)))
			goto fail;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_node_getsum_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_NODE_GETSUM *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_CKSUMTYPE cksumtype	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_NODE_GETSUM *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_NODE_GETSUM))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_node_getsum,
			ROBIN_MSG_NODE_GETSUM, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_GETSUM(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_NODE_GETSUM(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->cksumtype = cksumtype;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_lookup_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_LOOKUP *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_LOOKUP *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_LOOKUP))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_lookup,
			ROBIN_MSG_LOOKUP, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_LOOKUP(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_LOOKUP(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_LOOKUP(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_readdir_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_READDIR *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const int32_t *limit	/* int32_t */,
		const RobinDirentry *last	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_READDIR *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_READDIR))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_readdir,
			ROBIN_MSG_READDIR, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_READDIR(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_READDIR(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (limit) {
		if ((msg->limit = calloc(1, sizeof(*msg->limit))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->limit = *limit;
	}
	if (last) {
		if ((msg->last = calloc(1, sizeof(*msg->last))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDirentry(last, msg->last)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirlink_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRLINK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		ROBIN_TYPE type	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRLINK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRLINK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirlink,
			ROBIN_MSG_DIRLINK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRLINK(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRLINK(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRLINK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_DIRLINK(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	msg->type = type;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirunlink_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRUNLINK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRUNLINK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRUNLINK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirunlink,
			ROBIN_MSG_DIRUNLINK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRUNLINK(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRUNLINK(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRUNLINK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_DIRUNLINK(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirrelink_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRRELINK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		ROBIN_TYPE type	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRRELINK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRRELINK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirrelink,
			ROBIN_MSG_DIRRELINK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRELINK(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRELINK(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRELINK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRELINK(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	msg->type = type;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dircreate_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRCREATE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRCREATE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRCREATE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dircreate,
			ROBIN_MSG_DIRCREATE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRCREATE(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRCREATE(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl) {
		if ((msg->hdl = calloc(1, sizeof(*msg->hdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(hdl, msg->hdl)))
			goto fail;
	}
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_DIRCREATE(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_DIRCREATE(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->lock = *lock;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirsymlink_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRSYMLINK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinFilename *dest	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRSYMLINK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRSYMLINK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirsymlink,
			ROBIN_MSG_DIRSYMLINK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRSYMLINK(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRSYMLINK(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl) {
		if ((msg->hdl = calloc(1, sizeof(*msg->hdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(hdl, msg->hdl)))
			goto fail;
	}
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_DIRSYMLINK(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_DIRSYMLINK(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (dest == NULL) {
		log_warnx("DEBUG: ROBIN_DIRSYMLINK(RobinFilename dest) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(dest, &msg->dest)))
		goto fail;
	if (lock) {
		if ((msg->lock = calloc(1, sizeof(*msg->lock))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->lock = *lock;
	}
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirrename_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRRENAME *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinHandle *oldphdl	/* SEQUENCE */,
		const RobinFilename *oldname	/* OCTETSTRING */,
		const RobinHandle *newphdl	/* SEQUENCE */,
		const RobinFilename *newname	/* OCTETSTRING */,
		ROBIN_TYPE type	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRRENAME *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRRENAME))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirrename,
			ROBIN_MSG_DIRRENAME, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRENAME(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRENAME(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (oldphdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRENAME(RobinHandle oldphdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(oldphdl, &msg->oldphdl)))
		goto fail;
	if (oldname == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRENAME(RobinFilename oldname) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(oldname, &msg->oldname)))
		goto fail;
	if (newphdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRENAME(RobinHandle newphdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(newphdl, &msg->newphdl)))
		goto fail;
	if (newname == NULL) {
		log_warnx("DEBUG: ROBIN_DIRRENAME(RobinFilename newname) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(newname, &msg->newname)))
		goto fail;
	msg->type = type;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirhistget_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRHISTGET *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		int32_t last	/* int32_t */,
		int32_t limit	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRHISTGET *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRHISTGET))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirhistget,
			ROBIN_MSG_DIRHISTGET, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRHISTGET(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRHISTGET(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_DIRHISTGET(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	msg->last = last;
	msg->limit = limit;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_dirhistset_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DIRHISTSET *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		int32_t limit	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DIRHISTSET *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DIRHISTSET))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_dirhistset,
			ROBIN_MSG_DIRHISTSET, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DIRHISTSET(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_DIRHISTSET(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (name) {
		if ((msg->name = calloc(1, sizeof(*msg->name))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinFilename(name, msg->name)))
			goto fail;
	}
	msg->limit = limit;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_create_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_CREATE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *owner	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_CREATE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_CREATE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_create,
			ROBIN_MSG_GROUP_CREATE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_CREATE(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (owner == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_CREATE(RobinPrincipal owner) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(owner, &msg->owner)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_delete_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_DELETE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_DELETE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_DELETE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_delete,
			ROBIN_MSG_GROUP_DELETE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_DELETE(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_modify_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_MODIFY *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *owner	/* SEQUENCE */,
		const RobinGroupRight *public	/* BITSTRING */,
		const RobinGroupRight *private	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_GROUP_MODIFY *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_MODIFY))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_modify,
			ROBIN_MSG_GROUP_MODIFY, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_MODIFY(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (owner) {
		if ((msg->owner = calloc(1, sizeof(*msg->owner))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(owner, msg->owner)))
			goto fail;
	}
	if (public) {
		if ((msg->public = calloc(1, sizeof(*msg->public))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinGroupRight(public, msg->public)))
			goto fail;
	}
	if (private) {
		if ((msg->private = calloc(1, sizeof(*msg->private))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinGroupRight(private, msg->private)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_rename_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_RENAME *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *old_group	/* SEQUENCE */,
		const RobinPrincipal *new_group	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_RENAME *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_RENAME))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_rename,
			ROBIN_MSG_GROUP_RENAME, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (old_group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_RENAME(RobinPrincipal old_group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(old_group, &msg->old_group)))
		goto fail;
	if (new_group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_RENAME(RobinPrincipal new_group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(new_group, &msg->new_group)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_add_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_ADD *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *user	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_ADD *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_ADD))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_add,
			ROBIN_MSG_GROUP_ADD, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_ADD(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (user == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_ADD(RobinPrincipal user) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(user, &msg->user)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_del_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_DEL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *user	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_DEL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_DEL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_del,
			ROBIN_MSG_GROUP_DEL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_DEL(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (user == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_DEL(RobinPrincipal user) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(user, &msg->user)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_get_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_GET *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_GET *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_GET))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_get,
			ROBIN_MSG_GROUP_GET, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_GET(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_put_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_PUT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipals *users	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_GROUP_PUT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_PUT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_put,
			ROBIN_MSG_GROUP_PUT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_PUT(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (users == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_PUT(RobinPrincipals users) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipals(users, &msg->users)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_group_eval_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_GROUP_EVAL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *user	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_GROUP_EVAL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_GROUP_EVAL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_group_eval,
			ROBIN_MSG_GROUP_EVAL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (group == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_EVAL(RobinPrincipal group) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(group, &msg->group)))
		goto fail;
	if (user == NULL) {
		log_warnx("DEBUG: ROBIN_GROUP_EVAL(RobinPrincipal user) == NULL");
		abort();
	}
	if ((ret = copy_RobinPrincipal(user, &msg->user)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_part_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_PART *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinDiskFlags *diskflags	/* BITSTRING */,
		const RobinPartition *partition	/* OCTETSTRING */,
		int64_t partspace	/* int64_t */,
		int64_t usedspace	/* int64_t */,
		int64_t freespace	/* int64_t */,
		int64_t partnodes	/* int64_t */,
		int64_t usednodes	/* int64_t */,
		int64_t freenodes	/* int64_t */,
		int64_t neednodes	/* int64_t */,
		int64_t maxblock	/* int64_t */,
		const RobinTime *lastmount	/* SEQUENCE */,
		const RobinDiskStats *totperf	/* SEQUENCE */,
		const RobinDiskStats *curperf	/* SEQUENCE */,
		const RobinEncryptionKey *tokenkey	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_PART *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_PART))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_part,
			ROBIN_MSG_IHAVE_PART, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_PART(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	if (diskflags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_PART(RobinDiskFlags diskflags) == NULL");
		abort();
	}
	if ((ret = copy_RobinDiskFlags(diskflags, &msg->diskflags)))
		goto fail;
	if (partition == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_PART(RobinPartition partition) == NULL");
		abort();
	}
	if ((ret = copy_RobinPartition(partition, &msg->partition)))
		goto fail;
	msg->partspace = partspace;
	msg->usedspace = usedspace;
	msg->freespace = freespace;
	msg->partnodes = partnodes;
	msg->usednodes = usednodes;
	msg->freenodes = freenodes;
	msg->neednodes = neednodes;
	msg->maxblock = maxblock;
	if (lastmount == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_PART(RobinTime lastmount) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(lastmount, &msg->lastmount)))
		goto fail;
	if (totperf) {
		if ((msg->totperf = calloc(1, sizeof(*msg->totperf))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskStats(totperf, msg->totperf)))
			goto fail;
	}
	if (curperf) {
		if ((msg->curperf = calloc(1, sizeof(*msg->curperf))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskStats(curperf, msg->curperf)))
			goto fail;
	}
	if (tokenkey) {
		if ((msg->tokenkey = calloc(1, sizeof(*msg->tokenkey))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinEncryptionKey(tokenkey, msg->tokenkey)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_volume_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_VOLUME *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinFilename *selfname	/* OCTETSTRING */,
		const RobinHandle *roothdl	/* SEQUENCE */,
		const RobinTime *atime	/* SEQUENCE */,
		const RobinTime *mtime	/* SEQUENCE */,
		const int64_t *realsize	/* int64_t */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_VOLUME *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_VOLUME))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_volume,
			ROBIN_MSG_IHAVE_VOLUME, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_VOLUME(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_VOLUME(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_VOLUME(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}
	if (selfname) {
		if ((msg->selfname = calloc(1, sizeof(*msg->selfname))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinFilename(selfname, msg->selfname)))
			goto fail;
	}
	if (roothdl == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_VOLUME(RobinHandle roothdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(roothdl, &msg->roothdl)))
		goto fail;
	if (atime == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_VOLUME(RobinTime atime) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(atime, &msg->atime)))
		goto fail;
	if (mtime == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_VOLUME(RobinTime mtime) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(mtime, &msg->mtime)))
		goto fail;
	if (realsize) {
		if ((msg->realsize = calloc(1, sizeof(*msg->realsize))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->realsize = *realsize;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_node_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_NODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_TYPE type	/* int32_t */,
		int64_t size	/* int64_t */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinTime *atime	/* SEQUENCE */,
		const RobinTime *mtime	/* SEQUENCE */,
		const RobinPrincipal *muser	/* SEQUENCE */,
		const int64_t *realsize	/* int64_t */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_NODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_NODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_node,
			ROBIN_MSG_IHAVE_NODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_NODE(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_NODE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->type = type;
	msg->size = size;
	if (sum == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_NODE(RobinChecksum sum) == NULL");
		abort();
	}
	if ((ret = copy_RobinChecksum(sum, &msg->sum)))
		goto fail;
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}
	if (atime == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_NODE(RobinTime atime) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(atime, &msg->atime)))
		goto fail;
	if (mtime == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_NODE(RobinTime mtime) == NULL");
		abort();
	}
	if ((ret = copy_RobinTime(mtime, &msg->mtime)))
		goto fail;
	if (muser) {
		if ((msg->muser = calloc(1, sizeof(*msg->muser))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(muser, msg->muser)))
			goto fail;
	}
	if (realsize) {
		if ((msg->realsize = calloc(1, sizeof(*msg->realsize))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		*msg->realsize = *realsize;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_route_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_ROUTE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		int32_t rtype	/* int32_t */,
		int32_t ttl	/* int32_t */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_ROUTE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_ROUTE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_route,
			ROBIN_MSG_IHAVE_ROUTE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_ROUTE(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_ROUTE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->prefix = prefix;
	msg->rtype = rtype;
	msg->ttl = ttl;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_finished_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_FINISHED *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_FINISHED *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_FINISHED))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_finished,
			ROBIN_MSG_IHAVE_FINISHED, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_FINISHED(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_group_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_GROUP *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinGroupFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_GROUP *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_GROUP))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_group,
			ROBIN_MSG_IHAVE_GROUP, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_GROUP(RobinGroupFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinGroupFlags(flags, &msg->flags)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_trans_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_TRANS *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		int64_t append	/* int64_t */,
		const unsigned char *txid, size_t txidlen)
{
	struct robin_state *rs;
	ROBIN_IHAVE_TRANS *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_TRANS))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_trans,
			ROBIN_MSG_IHAVE_TRANS, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_TRANS(RobinTransFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinTransFlags(flags, &msg->flags)))
		goto fail;
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_TRANS(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	msg->offset = offset;
	msg->length = length;
	msg->append = append;
	if (txid == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_TRANS(OCTETSTRING txid) == NULL");
		abort();
	}
	msg->txid.length = txidlen;
	if ((msg->txid.data = malloc(msg->txid.length)) == NULL)
		goto fail;
	bcopy(txid, msg->txid.data, msg->txid.length);

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_withdraw_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_WITHDRAW *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_TYPE type	/* int32_t */,
		int32_t errorcode	/* int32_t */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_WITHDRAW *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_WITHDRAW))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_withdraw,
			ROBIN_MSG_IHAVE_WITHDRAW, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_WITHDRAW(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl) {
		if ((msg->vhdl = calloc(1, sizeof(*msg->vhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(vhdl, msg->vhdl)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_WITHDRAW(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->type = type;
	msg->errorcode = errorcode;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_ihave_protect_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_IHAVE_PROTECT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_IHAVE_PROTECT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_IHAVE_PROTECT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_ihave_protect,
			ROBIN_MSG_IHAVE_PROTECT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_PROTECT(RobinRouterFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinRouterFlags(flags, &msg->flags)))
		goto fail;
	if (rules == NULL) {
		log_warnx("DEBUG: ROBIN_IHAVE_PROTECT(RobinProtectNodes rules) == NULL");
		abort();
	}
	if ((ret = copy_RobinProtectNodes(rules, &msg->rules)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_getroot_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_GETROOT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_GETROOT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_GETROOT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_getroot,
			ROBIN_MSG_VOLUME_GETROOT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_GETROOT(RobinNodeFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinNodeFlags(flags, &msg->flags)))
		goto fail;
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_GETROOT(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_setroot_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_SETROOT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_SETROOT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_SETROOT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_setroot,
			ROBIN_MSG_VOLUME_SETROOT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_SETROOT(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_SETROOT(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_create_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_CREATE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinQuota *quota	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_CREATE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_CREATE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_create,
			ROBIN_MSG_VOLUME_CREATE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_CREATE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_CREATE(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (quota == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_CREATE(RobinQuota quota) == NULL");
		abort();
	}
	if ((ret = copy_RobinQuota(quota, &msg->quota)))
		goto fail;
	if (name) {
		if ((msg->name = calloc(1, sizeof(*msg->name))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinFilename(name, msg->name)))
			goto fail;
	}
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}
	if (rules) {
		if ((msg->rules = calloc(1, sizeof(*msg->rules))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinProtectNodes(rules, msg->rules)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_mknode_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_MKNODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_MKNODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_MKNODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_mknode,
			ROBIN_MSG_VOLUME_MKNODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_MKNODE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl) {
		if ((msg->hdl = calloc(1, sizeof(*msg->hdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(hdl, msg->hdl)))
			goto fail;
	}
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_MKNODE(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_chnode_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_CHNODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_CHNODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_CHNODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_chnode,
			ROBIN_MSG_VOLUME_CHNODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_CHNODE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_CHNODE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (attr == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_CHNODE(RobinAttributes attr) == NULL");
		abort();
	}
	if ((ret = copy_RobinAttributes(attr, &msg->attr)))
		goto fail;
	if (sum) {
		if ((msg->sum = calloc(1, sizeof(*msg->sum))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinChecksum(sum, msg->sum)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_stnode_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_STNODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_STNODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_STNODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_stnode,
			ROBIN_MSG_VOLUME_STNODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_STNODE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_STNODE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_rmnode_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_RMNODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_RMNODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_RMNODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_rmnode,
			ROBIN_MSG_VOLUME_RMNODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_RMNODE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_RMNODE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_snapshot_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_SNAPSHOT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *dhdl	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_SNAPSHOT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_SNAPSHOT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_snapshot,
			ROBIN_MSG_VOLUME_SNAPSHOT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_SNAPSHOT(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (dhdl) {
		if ((msg->dhdl = calloc(1, sizeof(*msg->dhdl))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinHandle(dhdl, msg->dhdl)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_dirlink_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_DIRLINK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_DIRLINK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_DIRLINK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_dirlink,
			ROBIN_MSG_VOLUME_DIRLINK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRLINK(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRLINK(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRLINK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRLINK(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRLINK(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_dirunlink_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_DIRUNLINK *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_DIRUNLINK *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_DIRUNLINK))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_dirunlink,
			ROBIN_MSG_VOLUME_DIRUNLINK, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRUNLINK(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (phdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRUNLINK(RobinHandle phdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(phdl, &msg->phdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRUNLINK(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (name == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRUNLINK(RobinFilename name) == NULL");
		abort();
	}
	if ((ret = copy_RobinFilename(name, &msg->name)))
		goto fail;
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_DIRUNLINK(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_vrnode_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_VRNODE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_VRNODE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_VRNODE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_vrnode,
			ROBIN_MSG_VOLUME_VRNODE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_VRNODE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_VRNODE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_vrsize_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_VRSIZE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t size	/* int64_t */,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_VRSIZE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_VRSIZE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_vrsize,
			ROBIN_MSG_VOLUME_VRSIZE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_VRSIZE(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_VRSIZE(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	msg->size = size;
	if (token) {
		if ((msg->token = calloc(1, sizeof(*msg->token))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinToken(token, msg->token)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_racl_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_RACL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_RACL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_RACL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_racl,
			ROBIN_MSG_VOLUME_RACL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_RACL(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_RACL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (principal) {
		if ((msg->principal = calloc(1, sizeof(*msg->principal))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(principal, msg->principal)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_volume_wacl_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_VOLUME_WACL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinRightsList *append	/* SEQUENCEOF */,
		const RobinRightsList *change	/* SEQUENCEOF */,
		const RobinRightsList *delete	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_VOLUME_WACL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_VOLUME_WACL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_volume_wacl,
			ROBIN_MSG_VOLUME_WACL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (vhdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_WACL(RobinHandle vhdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(vhdl, &msg->vhdl)))
		goto fail;
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_VOLUME_WACL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (append) {
		if ((msg->append = calloc(1, sizeof(*msg->append))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinRightsList(append, msg->append)))
			goto fail;
	}
	if (change) {
		if ((msg->change = calloc(1, sizeof(*msg->change))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinRightsList(change, msg->change)))
			goto fail;
	}
	if (delete) {
		if ((msg->delete = calloc(1, sizeof(*msg->delete))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinRightsList(delete, msg->delete)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_token_verify_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TOKEN_VERIFY *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinToken *token	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_TOKEN_VERIFY *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TOKEN_VERIFY))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_token_verify,
			ROBIN_MSG_TOKEN_VERIFY, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TOKEN_VERIFY(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_token_put_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TOKEN_PUT *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinToken *token	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_TOKEN_PUT *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TOKEN_PUT))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_token_put,
			ROBIN_MSG_TOKEN_PUT, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (token == NULL) {
		log_warnx("DEBUG: ROBIN_TOKEN_PUT(RobinToken token) == NULL");
		abort();
	}
	if ((ret = copy_RobinToken(token, &msg->token)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_token_get_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TOKEN_GET *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_TOKEN_GET *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TOKEN_GET))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_token_get,
			ROBIN_MSG_TOKEN_GET, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_TOKEN_GET(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_token_del_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_TOKEN_DEL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_TOKEN_DEL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_TOKEN_DEL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_token_del,
			ROBIN_MSG_TOKEN_DEL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (hdl == NULL) {
		log_warnx("DEBUG: ROBIN_TOKEN_DEL(RobinHandle hdl) == NULL");
		abort();
	}
	if ((ret = copy_RobinHandle(hdl, &msg->hdl)))
		goto fail;
	if (disk) {
		if ((msg->disk = calloc(1, sizeof(*msg->disk))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDisk(disk, msg->disk)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_compound_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_COMPOUND *callback, void *arg,
		const RobinPrincipal *proxyuser)
{
	struct robin_state *rs;
	ROBIN_COMPOUND *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_COMPOUND))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_compound,
			ROBIN_MSG_COMPOUND, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disk_initialize_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISK_INITIALIZE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_DISK_INITIALIZE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISK_INITIALIZE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disk_initialize,
			ROBIN_MSG_DISK_INITIALIZE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_INITIALIZE(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	if (flags == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_INITIALIZE(RobinDiskFlags flags) == NULL");
		abort();
	}
	if ((ret = copy_RobinDiskFlags(flags, &msg->flags)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disk_modify_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISK_MODIFY *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_DISK_MODIFY *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISK_MODIFY))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disk_modify,
			ROBIN_MSG_DISK_MODIFY, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_MODIFY(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	if (flags) {
		if ((msg->flags = calloc(1, sizeof(*msg->flags))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskFlags(flags, msg->flags)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disk_recover_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISK_RECOVER *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_DISK_RECOVER *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISK_RECOVER))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disk_recover,
			ROBIN_MSG_DISK_RECOVER, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_RECOVER(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	if (flags) {
		if ((msg->flags = calloc(1, sizeof(*msg->flags))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskFlags(flags, msg->flags)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disk_balance_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISK_BALANCE *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */,
		const RobinDiskTarget *target	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_DISK_BALANCE *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISK_BALANCE))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disk_balance,
			ROBIN_MSG_DISK_BALANCE, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_BALANCE(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	if (flags) {
		if ((msg->flags = calloc(1, sizeof(*msg->flags))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskFlags(flags, msg->flags)))
			goto fail;
	}
	if (target == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_BALANCE(RobinDiskTarget target) == NULL");
		abort();
	}
	if ((ret = copy_RobinDiskTarget(target, &msg->target)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disk_powerup_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISK_POWERUP *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_DISK_POWERUP *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISK_POWERUP))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disk_powerup,
			ROBIN_MSG_DISK_POWERUP, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_POWERUP(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	if (flags) {
		if ((msg->flags = calloc(1, sizeof(*msg->flags))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskFlags(flags, msg->flags)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_disk_powerdown_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_DISK_POWERDOWN *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	struct robin_state *rs;
	ROBIN_DISK_POWERDOWN *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_DISK_POWERDOWN))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_disk_powerdown,
			ROBIN_MSG_DISK_POWERDOWN, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (disk == NULL) {
		log_warnx("DEBUG: ROBIN_DISK_POWERDOWN(RobinDisk disk) == NULL");
		abort();
	}
	if ((ret = copy_RobinDisk(disk, &msg->disk)))
		goto fail;
	if (flags) {
		if ((msg->flags = calloc(1, sizeof(*msg->flags))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinDiskFlags(flags, msg->flags)))
			goto fail;
	}

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_protect_get_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_PROTECT_GET *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinProtectSource *source	/* SEQUENCE */)
{
	struct robin_state *rs;
	ROBIN_PROTECT_GET *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PROTECT_GET))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_protect_get,
			ROBIN_MSG_PROTECT_GET, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (source == NULL) {
		log_warnx("DEBUG: ROBIN_PROTECT_GET(RobinProtectSource source) == NULL");
		abort();
	}
	if ((ret = copy_RobinProtectSource(source, &msg->source)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_protect_add_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_PROTECT_ADD *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_PROTECT_ADD *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PROTECT_ADD))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_protect_add,
			ROBIN_MSG_PROTECT_ADD, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (rules == NULL) {
		log_warnx("DEBUG: ROBIN_PROTECT_ADD(RobinProtectNodes rules) == NULL");
		abort();
	}
	if ((ret = copy_RobinProtectNodes(rules, &msg->rules)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}

int
robin_protect_del_api(robin_context context, robin_con con, const RobinHost *host,
		RCB_PROTECT_DEL *callback, void *arg,
		const RobinPrincipal *proxyuser,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	struct robin_state *rs;
	ROBIN_PROTECT_DEL *msg = NULL;
	int ret = ROBIN_SUCCESS;

	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(ROBIN_PROTECT_DEL))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_protect_del,
			ROBIN_MSG_PROTECT_DEL, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
	if (rules == NULL) {
		log_warnx("DEBUG: ROBIN_PROTECT_DEL(RobinProtectNodes rules) == NULL");
		abort();
	}
	if ((ret = copy_RobinProtectNodes(rules, &msg->rules)))
		goto fail;

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
}
