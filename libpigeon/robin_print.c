/* $Gateweaver: robin_print.c,v 1.11 2007/05/31 16:23:09 cvs Exp $ */
/*
 * Copyright (c) 2007 Christopher Maxwell.  All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <vis.h>
#include "robin_locl.h"

#ifndef lint
RCSID("$Gateweaver: robin_print.c,v 1.11 2007/05/31 16:23:09 cvs Exp $");
#endif

const char *
robin_print_msgtype(ROBIN_MSGTYPE type)
{
	static char number[12];

	switch (type) {
		case ROBIN_MSG_GETROOT:			return "GETROOT";
		case ROBIN_MSG_GETROUTE:		return "GETROUTE";
		case ROBIN_MSG_GETDISK:			return "GETDISK";
		case ROBIN_MSG_GETCLIENT:		return "GETCLIENT";
		case ROBIN_MSG_GETOID:			return "GETOID";
		case ROBIN_MSG_SETOID:			return "SETOID";
		case ROBIN_MSG_GETLOCK:			return "GETLOCK";
		case ROBIN_MSG_GETACTION:		return "GETACTION";
		case ROBIN_MSG_GETTRANS:		return "GETTRANS";
		case ROBIN_MSG_PING:			return "PING";
		case ROBIN_MSG_PONG:			return "PONG";
		case ROBIN_MSG_SETCLIENTID:		return "SETCLID";
		case ROBIN_MSG_SETCON:			return "SETCON";
		case ROBIN_MSG_DISCONNECT:		return "DISCON";
		case ROBIN_MSG_REFRESH:			return "REFRESH";
		case ROBIN_MSG_STATUS:			return "STATUS";
		case ROBIN_MSG_STATUSHDL:		return "STATUS";
		case ROBIN_MSG_STATUSHDLSUM:	return "STATUS";
		case ROBIN_MSG_STATUSROUTE:		return "STATUS";
		case ROBIN_MSG_STATUSLOCK:		return "STATUS";
		case ROBIN_MSG_STATUSINFO:		return "STATUS";
		case ROBIN_MSG_STATUSACL:		return "STATUS";
		case ROBIN_MSG_STATUSDATA:		return "STATUS";
		case ROBIN_MSG_STATUSDIRENT:	return "STATUS";
		case ROBIN_MSG_STATUSTOKEN:		return "STATUS";
		case ROBIN_MSG_STATUSDISK:		return "STATUS";
		case ROBIN_MSG_STATUSHOST:		return "STATUS";
		case ROBIN_MSG_STATUSGROUP:		return "STATUS";
		case ROBIN_MSG_STATUSOID:		return "STATUS";
		case ROBIN_MSG_STATUSPROTECT:	return "STATUS";
		case ROBIN_MSG_STATUSSYNC:		return "STATUS";
		case ROBIN_MSG_MKNODE:			return "MKNODE";
		case ROBIN_MSG_MKSYM:			return "MKSYM";
		case ROBIN_MSG_OPEN:			return "OPEN";
		case ROBIN_MSG_UNLOCK:			return "UNLOCK";
		case ROBIN_MSG_GETATTR:			return "GETATTR";
		case ROBIN_MSG_PUTATTR:			return "PUTATTR";
		case ROBIN_MSG_GETACL:			return "GETACL";
		case ROBIN_MSG_PUTACL:			return "PUTACL";
		case ROBIN_MSG_READ:			return "READ";
		case ROBIN_MSG_WRITE:			return "WRITE";
		case ROBIN_MSG_APPEND:			return "APPEND";
		case ROBIN_MSG_TRANS_START:		return "TSTART";
		case ROBIN_MSG_TRANS_WRITE:		return "TWRITE";
		case ROBIN_MSG_TRANS_APPEND:	return "TAPPEND";
		case ROBIN_MSG_TRANS_READ:		return "TREAD";
		case ROBIN_MSG_TRANS_FINISH:	return "TFINISH";
		case ROBIN_MSG_NODE_PUT:		return "NODEPUT";
		case ROBIN_MSG_NODE_DEL:		return "NODEDEL";
		case ROBIN_MSG_NODE_COW:		return "NODECOW";
		case ROBIN_MSG_NODE_SYNC:		return "NODESYNC";
		case ROBIN_MSG_NODE_XFER:		return "NODEXFER";
		case ROBIN_MSG_NODE_SNAP:		return "NODESYNC";
		case ROBIN_MSG_NODE_GETSUM:		return "NODEGTSUM";
		case ROBIN_MSG_TRANS_ABORT:		return "TABORT";
		case ROBIN_MSG_TRANS_SYNC:		return "TSYNC";
		case ROBIN_MSG_LOOKUP:			return "LOOKUP";
		case ROBIN_MSG_READDIR:			return "READDIR";
		case ROBIN_MSG_DIRLINK:			return "DIRLINK";
		case ROBIN_MSG_DIRUNLINK:		return "DIRUNLINK";
		case ROBIN_MSG_DIRRELINK:		return "DIRRELINK";
		case ROBIN_MSG_GROUP_CREATE:	return "GCREATE";
		case ROBIN_MSG_GROUP_DELETE:	return "GDELETE";
		case ROBIN_MSG_GROUP_MODIFY:	return "GMODIFY";
		case ROBIN_MSG_GROUP_RENAME:	return "GRENAME";
		case ROBIN_MSG_GROUP_ADD:		return "GADD";
		case ROBIN_MSG_GROUP_DEL:		return "GDEL";
		case ROBIN_MSG_GROUP_GET:		return "GGET";
		case ROBIN_MSG_GROUP_PUT:		return "GPUT";
		case ROBIN_MSG_GROUP_EVAL:		return "GEVAL";
		case ROBIN_MSG_IHAVE_PART:		return "IHAVEPRT";
		case ROBIN_MSG_IHAVE_VOLUME:	return "IHAVEVOL";
		case ROBIN_MSG_IHAVE_NODE:		return "IHAVENOD";
		case ROBIN_MSG_IHAVE_ROUTE:		return "IHAVERTE";
		case ROBIN_MSG_IHAVE_FINISHED:	return "IHAVEFIN";
		case ROBIN_MSG_IHAVE_GROUP:		return "IHAVEGRP";
		case ROBIN_MSG_IHAVE_TRANS:		return "IHAVETXN";
		case ROBIN_MSG_IHAVE_WITHDRAW:	return "IHAVENOT";
		case ROBIN_MSG_IHAVE_PROTECT:	return "IHAVEPRO";
		case ROBIN_MSG_VOLUME_GETROOT:	return "VGETROOT";
		case ROBIN_MSG_VOLUME_SETROOT:	return "VSETROOT";
		case ROBIN_MSG_VOLUME_CREATE:	return "VCREATE";
		case ROBIN_MSG_VOLUME_MKNODE:	return "VMKNODE";
		case ROBIN_MSG_VOLUME_CHNODE:	return "VCHNODE";
		case ROBIN_MSG_VOLUME_STNODE:	return "VSTNODE";
		case ROBIN_MSG_VOLUME_RMNODE:	return "VRMNODE";
		case ROBIN_MSG_VOLUME_SNAPSHOT:	return "VSNAPSHOT";
		case ROBIN_MSG_VOLUME_DIRLINK:	return "VDIRLINK";
		case ROBIN_MSG_VOLUME_DIRUNLINK:return "VDIRUNLNK";
		case ROBIN_MSG_VOLUME_VRNODE:	return "VVRNODE";
		case ROBIN_MSG_VOLUME_VRSIZE:	return "VVRSIZE";
		case ROBIN_MSG_VOLUME_RACL:		return "VRACL";
		case ROBIN_MSG_VOLUME_WACL:		return "VWACL";
		case ROBIN_MSG_TOKEN_VERIFY:	return "TOKVERIFY";
		case ROBIN_MSG_TOKEN_PUT:		return "TOKPUT";
		case ROBIN_MSG_TOKEN_GET:		return "TOKGET";
		case ROBIN_MSG_TOKEN_DEL:		return "TOKDEL";
		case ROBIN_MSG_DIRCREATE:		return "DIRCREATE";
		case ROBIN_MSG_DIRSYMLINK:		return "SYMLINK";
		case ROBIN_MSG_DIRRENAME:		return "RENAME";
		case ROBIN_MSG_DIRHISTGET:		return "DIRHISTGT";
		case ROBIN_MSG_DIRHISTSET:		return "DIRHISTST";
		case ROBIN_MSG_COMPOUND:		return "COMPOUND";
		case ROBIN_MSG_DISK_INITIALIZE:	return "DINIT";
		case ROBIN_MSG_DISK_MODIFY:		return "DMODIFY";
		case ROBIN_MSG_DISK_RECOVER:	return "DRECOVER";
		case ROBIN_MSG_DISK_BALANCE:	return "DBALANCE";
		case ROBIN_MSG_DISK_POWERUP:	return "DPOWERUP";
		case ROBIN_MSG_DISK_POWERDOWN:	return "DPOWERDN";
		case ROBIN_MSG_PROTECT_GET:		return "PROTGET";
		case ROBIN_MSG_PROTECT_ADD:		return "PROTADD";
		case ROBIN_MSG_PROTECT_DEL:		return "PROTDEL";
	}
	snprintf(number, sizeof(number), "%d", type);
	return number;
}

const char *
robin_print_msg(ROBIN_MSGTYPE type, const RobinHeader *hdr)
{
	static tbstring sa;
	int ret = ROBIN_API_INVALID;

	if (tbstrprintf(&sa, "%-9s [%u] ", robin_print_msgtype(type), hdr->xid)) {
		tbstrfree(&sa);
		return "ERROR";
	}

#define PRINTMSG(T, fmt, args...)						\
	case ROBIN_MSG_##T: {								\
		const ROBIN_##T *msg = (const ROBIN_##T *)hdr;	\
		ret = tbstrprintfcat(&sa, fmt, ##args);			\
	} break

	switch (type) {

		/* MESSAGING */

		PRINTMSG(GETROOT, "flags=<%s>",
				print_RobinNodeFlags(msg->flags));
		PRINTMSG(GETROUTE, "%u.%u.%u.%u/%d limit %d",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->prefix, msg->limit);
		PRINTMSG(GETDISK, "disks %s",
				print_RobinDisks(msg->disks));
		PRINTMSG(GETCLIENT, "disks (%s) clients (%s)",
				print_RobinDisks(msg->disks),
				print_RobinPrincipals(msg->principals));
		PRINTMSG(GETOID, "oid %s",
				print_oid(msg->oid));
		PRINTMSG(SETOID, "oid %s",
				print_oid(msg->oid));
		PRINTMSG(GETLOCK, "%u.%u.%u.%u/%d princ %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->prefix, print_RobinPrincipal(msg->principal));
		PRINTMSG(GETACTION, "%u.%u.%u.%u/%d princ %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->prefix, print_RobinPrincipal(msg->principal));
		PRINTMSG(GETTRANS, "%u.%u.%u.%u/%d princ %s disk %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->prefix, print_RobinPrincipal(msg->principal),
				print_RobinDisk(msg->disk));

		/* CONNECTION */

		case ROBIN_MSG_PING:
			ret = ROBIN_SUCCESS;
			break;
		case ROBIN_MSG_PONG:
			ret = ROBIN_SUCCESS;
			break;
		PRINTMSG(SETCLIENTID, "clientid %s identity %s verifier %s",
				print_RobinData(&msg->clientid),
				print_RobinData_2(&msg->identity),
				print_RobinEncryptionKey(&msg->verifier));
		PRINTMSG(SETCON, "flags=<%s>",
				print_RobinConFlags(msg->flags));
		PRINTMSG(DISCONNECT, "flags=<%s> delay %s",
				print_RobinConFlags(msg->flags),
				print_RobinTime_delta(&msg->time));
		PRINTMSG(REFRESH, "%u.%u.%u.%u",
				msg->hdl ? msg->hdl->vol : 0, msg->hdl ? msg->hdl->ino : 0,
				msg->hdl ? msg->hdl->gen : 0, msg->hdl ? msg->hdl->ver : 0);

		PRINTMSG(STATUS, "[%u] %d",
				msg->rep.rxid, msg->rep.status);
		PRINTMSG(STATUSHDL, "[%u] %d hdl %u.%u.%u.%u lock %s",
				msg->rep.rxid, msg->rep.status,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinLock(msg->lock));
		PRINTMSG(STATUSHDLSUM, "[%u] %d hdl %u.%u.%u.%u sum %s lock %s",
				msg->rep.rxid, msg->rep.status,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinChecksum(&msg->sum),
				print_RobinLock(msg->lock));
		PRINTMSG(STATUSROUTE, "[%u] %d hdl %u.%u.%u.%u/%d %s %s %s ttl %d sum %s "
				"size %lld flags=<%s> atime %s",
				msg->rep.rxid, msg->rep.status,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->prefix,
				msg->rtype == RROUTE_DEAD ? "DEAD" :
				msg->rtype == RROUTE_PEER ? "PEER" :
				msg->rtype == RROUTE_WREN ? "WREN" :
				msg->rtype == RROUTE_IOWN ? "IOWN" :
				msg->rtype == RROUTE_FILTER ? "FILTER" : "UNKNOWN",
				robin_type(msg->ntype), print_RobinDisk(msg->disk),
				msg->ttl, print_RobinChecksum(msg->sum), msg->size,
				print_RobinRouterFlags(msg->flags),
				print_RobinTime_date_2(msg->atime));
		PRINTMSG(STATUSLOCK, "[%u] %d lock %s hosts %s tokens %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinLock(msg->lock),
				print_RobinHosts(msg->hosts),
				print_RobinTokens(msg->tokens));
		PRINTMSG(STATUSINFO, "[%u] %d %u.%u.%u.%u vhdl %u.%u.%u.%u attr %s "
				"sum %s lock %s",
				msg->rep.rxid, msg->rep.status,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->vhdl ? msg->vhdl->vol : 0, msg->vhdl ? msg->vhdl->ino : 0,
				msg->vhdl ? msg->vhdl->gen : 0, msg->vhdl ? msg->vhdl->ver : 0,
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(&msg->sum),
				print_RobinLock(msg->lock));
		PRINTMSG(STATUSACL, "[%u] %d acl %s lock %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinRightsList(&msg->acl),
				print_RobinLock(msg->lock));
		PRINTMSG(STATUSDATA, "[%u] %d data %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinData(&msg->data));
		PRINTMSG(STATUSDIRENT, "[%u] %d dir %s lock %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinDirentries(&msg->entries),
				print_RobinLock(msg->lock));
		PRINTMSG(STATUSTOKEN, "[%u] %d tok %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinToken(&msg->token));
		PRINTMSG(STATUSDISK, "[%u] %d disk %s space %lld/%lld nodes %lld/%lld "
				"rtt %lld.%06ds rbw %lld wbw %lld flags=<%s>",
				msg->rep.rxid, msg->rep.status,
				print_RobinDisk(&msg->disk),
				msg->usedspace, msg->freespace, msg->usednodes, msg->freenodes,
				msg->rttlatency.secs, msg->rttlatency.nsec,
				msg->rbandwidth, msg->wbandwidth,
				print_RobinDiskFlags(msg->flags));
		PRINTMSG(STATUSHOST, "[%u] %d host %s cid %s members %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinHost(&msg->host),
				print_RobinData(&msg->clientid),
				print_RobinPrincipals(&msg->principals));
		PRINTMSG(STATUSGROUP, "[%u] %d group %s owner %s public %s private %s "
				"users %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipal_2(msg->owner),
				msg->public ? print_RobinGroupRight(*msg->public) : "none",
				msg->private ? print_RobinGroupRight_2(*msg->private) : "none",
				print_RobinPrincipals(msg->users));
		PRINTMSG(STATUSOID, "[%u] %d oid %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinData(&msg->data));
		PRINTMSG(STATUSPROTECT, "[%u] %d rules %d",
				msg->rep.rxid, msg->rep.status,
				msg->rules.len);
		PRINTMSG(STATUSSYNC, "[%u] %d syncsum %s",
				msg->rep.rxid, msg->rep.status,
				print_RobinSyncChecksum(msg->syncsum));

		/* NODE OPERATION */

		PRINTMSG(MKNODE, "%u.%u.%u.%u flags=<%s> attr [%s] sum %s lock <%s> "
				"vhdl %s",
				msg->hdl ? msg->hdl->vol : 0, msg->hdl ? msg->hdl->ino : 0,
				msg->hdl ? msg->hdl->gen : 0, msg->hdl ? msg->hdl->ver : 0,
				print_RobinNodeFlags(msg->flags),
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(msg->sum),
				msg->lock ? print_ROBIN_LOCKTYPE(*msg->lock) : "none",
				print_RobinHandle(msg->vhdl));
		PRINTMSG(MKSYM, "%u.%u.%u.%u flags=<%s> attr [%s] dest %s "
				"lock <%s> vhdl %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinAttributes(&msg->attr),
				print_RobinData(&msg->dest),
				msg->lock ? print_ROBIN_LOCKTYPE(*msg->lock) : "none",
				print_RobinHandle(msg->vhdl));
		PRINTMSG(OPEN, "%u.%u.%u.%u flags=<%s> lock <%s> vhdl %s host %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->lock ? print_ROBIN_LOCKTYPE(*msg->lock) : "none",
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk));
		PRINTMSG(UNLOCK, "%u.%u.%u.%u flags=<%s> lock <%s> vhdl %s expiry %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->lock ? print_ROBIN_LOCKTYPE(*msg->lock) : "none",
				print_RobinHandle(msg->vhdl),
				print_RobinTime_delta(msg->expiry));
		PRINTMSG(GETATTR, "%u.%u.%u.%u flags=<%s> vhdl %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinHandle(msg->vhdl));
		PRINTMSG(PUTATTR, "%u.%u.%u.%u flags=<%s> attr [%s] sum %s vhdl %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(msg->sum),
				print_RobinHandle(msg->vhdl));
		PRINTMSG(GETACL, "%u.%u.%u.%u flags=<%s> princ %s vhdl %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinPrincipal(msg->principal),
				print_RobinHandle(msg->vhdl));
		PRINTMSG(PUTACL, "%u.%u.%u.%u flags=<%s> append %u change %u delete %u "
				"vhdl %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->append ? msg->append->len : 0,
				msg->change ? msg->change->len : 0,
				msg->delete ? msg->delete->len : 0,
				print_RobinHandle(msg->vhdl));

		/* NODE DATA */

		PRINTMSG(READ, "%u.%u.%u.%u off %lld len %lld token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->offset, msg->length,
				print_RobinToken(msg->token));
		PRINTMSG(WRITE, "%u.%u.%u.%u off %lld len %lld dlen %zd sum %s "
				"token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->offset, msg->length, msg->data.length,
				print_RobinChecksum(msg->sum),
				print_RobinToken(msg->token));
		PRINTMSG(APPEND, "%u.%u.%u.%u dlen %zd token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->data.length,
				print_RobinToken(msg->token));
		PRINTMSG(TRANS_START, "%u.%u.%u.%u flags=<%s> off %lld len %lld "
				"token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinTransFlags(msg->flags),
				msg->offset, msg->length,
				print_RobinToken(msg->token));
		PRINTMSG(TRANS_WRITE, "%s off %lld dlen %zd",
				print_RobinToken(&msg->token),
				msg->offset, msg->data.length);
		PRINTMSG(TRANS_APPEND, "%s dlen %zd",
				print_RobinToken(&msg->token),
				msg->data.length);
		PRINTMSG(TRANS_READ, "%s off %lld len %lld",
				print_RobinToken(&msg->token),
				msg->offset, msg->length);
		PRINTMSG(TRANS_FINISH, "%s flags=<%s> sum %s",
				print_RobinToken(&msg->token),
				print_RobinTransFlags(msg->flags),
				print_RobinChecksum(msg->sum));
		PRINTMSG(TRANS_ABORT, "%s flags=<%s> txid %s",
				print_RobinToken(&msg->token),
				print_RobinTransFlags(msg->flags),
				print_RobinData(msg->txid));
		PRINTMSG(TRANS_SYNC, "%s flags=<%s> sflags=<%s> sumtype %s cmds %s",
				print_RobinToken(&msg->token),
				print_RobinTransFlags(msg->flags),
				print_RobinSyncFlags(msg->sflags),
				print_ROBIN_CKSUMTYPE(msg->hardsumtype),
				print_RobinSyncCommands(&msg->cmds));

		/* NODE MANIPULATION */

		PRINTMSG(NODE_PUT, "%u.%u.%u.%u flags=<%s> type %s size %lld sum %s "
				"disk %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				robin_type(msg->type), msg->size,
				print_RobinChecksum(msg->sum),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(NODE_DEL, "%u.%u.%u.%u flags=<%s> disk %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(NODE_COW, "%u.%u.%u.%u flags=<%s> new %u.%u.%u.%u disk %s "
				"token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->nhdl.vol, msg->nhdl.ino, msg->nhdl.gen, msg->nhdl.ver,
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(NODE_SYNC, "%u.%u.%u.%u flags=<%s> disk %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(NODE_XFER, "%u.%u.%u.%u flags=<%s> disk %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(NODE_SNAP, "%u.%u.%u.%u flags=<%s> dhdl %u.%u.%u.%u vhdl %s "
				"disk %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->dhdl ? msg->dhdl->vol : 0, msg->dhdl ? msg->dhdl->ino : 0,
				msg->dhdl ? msg->dhdl->gen : 0, msg->dhdl ? msg->dhdl->ver : 0,
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(NODE_GETSUM, "%u.%u.%u.%u flags=<%s> type %d disk %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->cksumtype,
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));

		/* NAMESPACE */

		PRINTMSG(LOOKUP, "%u.%u.%u.%u flags=<%s> %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinData(&msg->name),
				print_RobinToken(msg->token));
		PRINTMSG(READDIR, "%u.%u.%u.%u flags=<%s> limit %d "
				"last %s token %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->limit ? *msg->limit : -1,
				print_RobinDirentry(msg->last),
				print_RobinToken(msg->token));
		PRINTMSG(DIRLINK, "%u.%u.%u.%u flags=<%s> %u.%u.%u.%u:%s:%s "
				"vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				robin_type(msg->type),
				print_RobinData(&msg->name),
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRUNLINK, "%u.%u.%u.%u flags=<%s> %u.%u.%u.%u:%s "
				"vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinData(&msg->name),
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRRELINK, "%u.%u.%u.%u flags=<%s> %u.%u.%u.%u:%s:%s "
				"vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				robin_type(msg->type),
				print_RobinData(&msg->name),
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRCREATE, "%u.%u.%u.%u flags=<%s> %u.%u.%u.%u:%s "
				"attr [%s] sum %s lock <%s> vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->hdl ? msg->hdl->vol : 0, msg->hdl ? msg->hdl->ino : 0,
				msg->hdl ? msg->hdl->gen : 0, msg->hdl ? msg->hdl->ver : 0,
				print_RobinData(&msg->name),
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(msg->sum),
				msg->lock ? print_ROBIN_LOCKTYPE(*msg->lock) : "none",
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRSYMLINK, "%u.%u.%u.%u flags=<%s> %u.%u.%u.%u:%s "
				"attr [%s] dest %s lock <%s> vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				msg->hdl ? msg->hdl->vol : 0, msg->hdl ? msg->hdl->ino : 0,
				msg->hdl ? msg->hdl->gen : 0, msg->hdl ? msg->hdl->ver : 0,
				print_RobinData(&msg->name),
				print_RobinAttributes(&msg->attr),
				print_RobinData_2(&msg->dest),
				msg->lock ? print_ROBIN_LOCKTYPE(*msg->lock) : "none",
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRRENAME, "%u.%u.%u.%u:%s -> %u.%u.%u.%u:%s "
				"flags=<%s> type %s vhdl %s disk %s token %s",
				msg->oldphdl.vol, msg->oldphdl.ino, msg->oldphdl.gen,
				msg->oldphdl.ver,
				print_RobinData(&msg->oldname),
				msg->newphdl.vol, msg->newphdl.ino, msg->newphdl.gen,
				msg->newphdl.ver,
				print_RobinData_2(&msg->newname),
				print_RobinNodeFlags(msg->flags),
				robin_type(msg->type),
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRHISTGET, "%u.%u.%u.%u flags=<%s> %s last %d limit %d "
				"vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinData(&msg->name),
				msg->last, msg->limit,
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));
		PRINTMSG(DIRHISTSET, "%u.%u.%u.%u flags=<%s> %s limit %d "
				"vhdl %s disk %s token %s",
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				print_RobinNodeFlags(msg->flags),
				print_RobinData(msg->name),
				msg->limit,
				print_RobinHandle(msg->vhdl),
				print_RobinDisk(msg->disk),
				print_RobinToken(msg->token));

		/* GROUP */

		PRINTMSG(GROUP_CREATE, "group %s owner %s",
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipal_2(&msg->owner));
		PRINTMSG(GROUP_DELETE, "group %s",
				print_RobinPrincipal(&msg->group));
		PRINTMSG(GROUP_MODIFY, "group %s owner %s public <%s> private <%s>",
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipal_2(msg->owner),
				msg->public ? print_RobinGroupRight(*msg->public) : "none",
				msg->private ? print_RobinGroupRight_2(*msg->private) : "none");
		PRINTMSG(GROUP_RENAME, "old %s new %s",
				print_RobinPrincipal(&msg->old_group),
				print_RobinPrincipal_2(&msg->new_group));
		PRINTMSG(GROUP_ADD, "group %s user %s",
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipal_2(&msg->user));
		PRINTMSG(GROUP_DEL, "group %s user %s",
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipal_2(&msg->user));
		PRINTMSG(GROUP_GET, "group %s",
				print_RobinPrincipal(&msg->group));
		PRINTMSG(GROUP_PUT, "group %s users %s",
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipals(&msg->users));
		PRINTMSG(GROUP_EVAL, "group %s user %s",
				print_RobinPrincipal(&msg->group),
				print_RobinPrincipal_2(&msg->user));

		/* IHAVE */

		PRINTMSG(IHAVE_PART, "part %s rflags=<%s> dflags=<%s> "
				"space %lld/%lld/%lld nodes %lld/%lld/%lld "
				"nmult %lld maxfile %lld last %s key %s",
				print_RobinData(&msg->partition),
				print_RobinRouterFlags(msg->flags),
				print_RobinDiskFlags(msg->diskflags),
				msg->partspace, msg->usedspace, msg->freespace,
				msg->partnodes, msg->usednodes, msg->freenodes,
				msg->neednodes, msg->maxblock,
				print_RobinTime_date(&msg->lastmount),
				print_RobinEncryptionKey(msg->tokenkey));
		PRINTMSG(IHAVE_VOLUME, "%u.%u.%u.%u flags=<%s> attr [%s] sum %s "
				"token %s self %s root %u.%u.%u.%u atime %s mtime %s "
				"real %lld",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				print_RobinRouterFlags(msg->flags),
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(msg->sum),
				print_RobinToken(msg->token),
				print_RobinData(msg->selfname),
				msg->roothdl.vol, msg->roothdl.ino, msg->roothdl.gen,
				msg->roothdl.ver,
				print_RobinTime_date(&msg->atime),
				print_RobinTime_date_2(&msg->mtime),
				msg->realsize ? *msg->realsize : 0);
		PRINTMSG(IHAVE_NODE, "%u.%u.%u.%u flags=<%s> vhdl %s type %s size %lld "
				"sum %s token %s atime %s mtime %s muser %s real %lld",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinRouterFlags(msg->flags),
				print_RobinHandle(msg->vhdl),
				robin_type(msg->type), msg->size,
				print_RobinChecksum(&msg->sum),
				print_RobinToken(msg->token),
				print_RobinTime_date(&msg->atime),
				print_RobinTime_date_2(&msg->mtime),
				print_RobinPrincipal(msg->muser),
				msg->realsize ? *msg->realsize : 0);
		PRINTMSG(IHAVE_ROUTE, "%u.%u.%u.%u/%d flags=<%s> type %d ttl %d",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->prefix,
				print_RobinRouterFlags(msg->flags),
				msg->rtype, msg->ttl);
		PRINTMSG(IHAVE_FINISHED, "flags=<%s>",
				print_RobinRouterFlags(msg->flags));
		PRINTMSG(IHAVE_GROUP, "flags=<%s>",
				print_RobinGroupFlags(msg->flags));
		PRINTMSG(IHAVE_TRANS, "%s flags=<%s> off %lld len %lld app %lld "
				"txid %s",
				print_RobinToken(&msg->token),
				print_RobinTransFlags(msg->flags),
				msg->offset, msg->length, msg->append,
				print_RobinData(&msg->txid));
		PRINTMSG(IHAVE_WITHDRAW, "%u.%u.%u.%u flags=<%s> vhdl %s type %s "
				"error %d",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinRouterFlags(msg->flags),
				print_RobinHandle(msg->vhdl),
				robin_type(msg->type), msg->errorcode);
		PRINTMSG(IHAVE_PROTECT, "flags=<%s> rules %u",
				print_RobinRouterFlags(msg->flags),
				msg->rules.len);

		/* VOLUME */

		PRINTMSG(VOLUME_GETROOT, "%u.%u.%u.%u flags=<%s>",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				print_RobinNodeFlags(msg->flags));
		PRINTMSG(VOLUME_SETROOT, "%u.%u.%u.%u root %u.%u.%u.%u",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver);
		PRINTMSG(VOLUME_CREATE, "%u.%u.%u.%u attr [%s] quota %lld/%lld "
				"name %s token %s rules %u",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				print_RobinAttributes(&msg->attr),
				msg->quota.space, msg->quota.nodes,
				print_RobinData(msg->name),
				print_RobinToken(msg->token),
				msg->rules ? msg->rules->len : 0);
		PRINTMSG(VOLUME_MKNODE, "%u.%u.%u.%u hdl %u.%u.%u.%u attr [%s] sum %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl ? msg->hdl->vol : 0, msg->hdl ? msg->hdl->ino : 0,
				msg->hdl ? msg->hdl->gen : 0, msg->hdl ? msg->hdl->ver : 0,
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(msg->sum));
		PRINTMSG(VOLUME_CHNODE, "%u.%u.%u.%u hdl %u.%u.%u.%u attr [%s] sum %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinAttributes(&msg->attr),
				print_RobinChecksum(msg->sum));
		PRINTMSG(VOLUME_STNODE, "%u.%u.%u.%u hdl %u.%u.%u.%u",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver);
		PRINTMSG(VOLUME_RMNODE, "%u.%u.%u.%u hdl %u.%u.%u.%u",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver);
		PRINTMSG(VOLUME_SNAPSHOT, "%u.%u.%u.%u hdl %u.%u.%u.%u",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->dhdl ? msg->dhdl->vol : 0, msg->dhdl ? msg->dhdl->ino : 0,
				msg->dhdl ? msg->dhdl->gen : 0, msg->dhdl ? msg->dhdl->ver : 0);
		PRINTMSG(VOLUME_DIRLINK, "%u.%u.%u.%u parent %u.%u.%u.%u "
				"child %u.%u.%u.%u:%s token %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinData(&msg->name),
				print_RobinToken(&msg->token));
		PRINTMSG(VOLUME_DIRUNLINK, "%u.%u.%u.%u parent %u.%u.%u.%u "
				"child %u.%u.%u.%u:%s token %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->phdl.vol, msg->phdl.ino, msg->phdl.gen, msg->phdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinData(&msg->name),
				print_RobinToken(&msg->token));
		PRINTMSG(VOLUME_VRNODE, "%u.%u.%u.%u hdl %u.%u.%u.%u token %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinToken(msg->token));
		PRINTMSG(VOLUME_VRSIZE, "%u.%u.%u.%u hdl %u.%u.%u.%u size %lld token %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->size, print_RobinToken(msg->token));
		PRINTMSG(VOLUME_RACL, "%u.%u.%u.%u hdl %u.%u.%u.%u princ %s",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinPrincipal(msg->principal));
		PRINTMSG(VOLUME_WACL, "%u.%u.%u.%u hdl %u.%u.%u.%u "
				"append %u change %u delete %u",
				msg->vhdl.vol, msg->vhdl.ino, msg->vhdl.gen, msg->vhdl.ver,
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				msg->append ? msg->append->len : 0,
				msg->change ? msg->change->len : 0,
				msg->delete ? msg->delete->len : 0);

		/* TOKEN */

		PRINTMSG(TOKEN_VERIFY, "%s",
				print_RobinToken(&msg->token));
		PRINTMSG(TOKEN_PUT, "%s disk %s",
				print_RobinToken(&msg->token),
				print_RobinDisk(msg->disk));
		PRINTMSG(TOKEN_GET, "%u.%u.%u.%u disk %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinDisk(msg->disk));
		PRINTMSG(TOKEN_DEL, "%u.%u.%u.%u disk %s",
				msg->hdl.vol, msg->hdl.ino, msg->hdl.gen, msg->hdl.ver,
				print_RobinDisk(msg->disk));

		/* COMPOUND */

		case ROBIN_MSG_COMPOUND:
			ret = ROBIN_SUCCESS;
			break;

		/* DISK */

		PRINTMSG(DISK_INITIALIZE, "%s flags=<%s>",
				print_RobinDisk(&msg->disk),
				print_RobinDiskFlags(msg->flags));
		PRINTMSG(DISK_MODIFY, "%s flags=<%s>",
				print_RobinDisk(&msg->disk),
				msg->flags ? print_RobinDiskFlags(*msg->flags) : "none");
		PRINTMSG(DISK_RECOVER, "%s flags=<%s>",
				print_RobinDisk(&msg->disk),
				msg->flags ? print_RobinDiskFlags(*msg->flags) : "none");
		PRINTMSG(DISK_BALANCE, "%s flags=<%s> target size %lld pcnt %d%%",
				print_RobinDisk(&msg->disk),
				msg->flags ? print_RobinDiskFlags(*msg->flags) : "none",
				msg->target.size ? *msg->target.size : -1,
				msg->target.percent ? *msg->target.percent : -1);
		PRINTMSG(DISK_POWERUP, "%s flags=<%s>",
				print_RobinDisk(&msg->disk),
				msg->flags ? print_RobinDiskFlags(*msg->flags) : "none");
		PRINTMSG(DISK_POWERDOWN, "%s flags=<%s>",
				print_RobinDisk(&msg->disk),
				msg->flags ? print_RobinDiskFlags(*msg->flags) : "none");

		/* PROTECT */

		PRINTMSG(PROTECT_GET, "%u.%u.%u.%u disk %s",
				msg->source.vhdl ? msg->source.vhdl->vol : 0,
				msg->source.vhdl ? msg->source.vhdl->ino : 0,
				msg->source.vhdl ? msg->source.vhdl->gen : 0,
				msg->source.vhdl ? msg->source.vhdl->ver : 0,
				print_RobinDisk(msg->source.disk));
		PRINTMSG(PROTECT_ADD, "rules %u",
				msg->rules.len);
		PRINTMSG(PROTECT_DEL, "rules %u",
				msg->rules.len);
	}

	if (ret) {
		if (tbstrcat(&sa, "ERROR")) {
			tbstrfree(&sa);
			return "ERROR";
		}
	}

	return sa.s;

#undef PRINTMSG
}

const char *
print_RobinDisk(const RobinDisk *disk)
{
	static tbstring sa;

	if (disk == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%s:%.*s",
				disk->hostname ? disk->hostname : "unknown",
				(int)disk->pid.length,
				(char *)disk->pid.data)) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinDisks(const RobinDisks *disks)
{
	static tbstring sa;
	unsigned int u;

	if (disks == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < disks->len; u++)
		if (tbstrprintfcat(&sa, "%s%s", u == 0 ? "" : ", ",
					print_RobinDisk(&disks->val[u]))) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_RobinPrincipal(const RobinPrincipal *princ)
{
	static tbstring sa;

	if (princ == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%s@%s", princ->name, princ->cell)) {
		tbstrfree(&sa);
		return "error";
	}

	return sa.s;
}

const char *
print_RobinPrincipal_2(const RobinPrincipal *princ)
{
	static tbstring sa;

	if (princ == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%s@%s", princ->name, princ->cell)) {
		tbstrfree(&sa);
		return "error";
	}

	return sa.s;
}

const char *
print_RobinPrincipals(const RobinPrincipals *princs)
{
	static tbstring sa;
	unsigned int u;

	if (princs == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < princs->len; u++)
		if (tbstrprintfcat(&sa, "%s%s", u == 0 ? "" : ", ",
					print_RobinPrincipal(&princs->val[u]))) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_oid(tb_oid oid)
{
	static tbstring sa;
	unsigned int u;

	if (oid.length == 0) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < oid.length; u++)
		if (tbstrprintfcat(&sa, "%s%d", u == 0 ? "" : ".",
					oid.components[u])) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_RobinTime_delta(const RobinTime *rt)
{
	static tbstring sa;
	time_t work, nsec;
	int neg = 0, secs, mins, hours, days, years;

	if (rt == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";

	work = rt->secs;
	nsec = rt->nsec;
	if (work < 0) {
		work = abs(work);
		neg = 1;
	}
	if (nsec < 0) {
		nsec = abs(nsec);
		neg = 1;
	}

	secs = work % 60;
	work /= 60;
	mins = work % 60;
	work /= 60;
	hours = work % 24;
	work /= 24;
	days = work % 365;
	work /= 365;
	years = work;

	if (neg)
		if ((tbstrprintfcat(&sa, "-")))
			goto fail;

	if (years > 0)
		if ((tbstrprintfcat(&sa, "%dy", years)))
			goto fail;

	if (days > 0)
		if ((tbstrprintfcat(&sa, "%dd", days)))
			goto fail;

	if (hours > 0)
		if ((tbstrprintfcat(&sa, "%dh", hours)))
			goto fail;

	if (mins > 0)
		if ((tbstrprintfcat(&sa, "%dm", mins)))
			goto fail;

	if (secs > 0 || nsec != 0) {
		if ((tbstrprintfcat(&sa, "%d", secs)))
			goto fail;
		if (rt->nsec != 0)
			if ((tbstrprintfcat(&sa, ".%06d", rt->nsec)))
				goto fail;
		if ((tbstrcat(&sa, "s")))
			goto fail;
	}

	if (years == 0 && hours == 0 && mins == 0 && secs == 0 && nsec == 0)
		if ((tbstrcat(&sa, "0s")))
			goto fail;

	return sa.s;

fail:
	tbstrfree(&sa);
	return "error";
}

const char *
print_RobinTime_date(const RobinTime *rt)
{
	static tbstring sa;
	char tbuf[sizeof("9999-12-31T23:59:60+0000")];
	time_t whence;

	if (rt == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	whence = rt->secs;
	strftime(tbuf, sizeof(tbuf), "%FT%T%z", localtime(&whence));
	if (tbstrcpy(&sa, tbuf)) {
		tbstrfree(&sa);
		return "error";
	}

	return sa.s;
}

const char *
print_RobinTime_date_2(const RobinTime *rt)
{
	static tbstring sa;
	char tbuf[sizeof("9999-12-31T23:59:60+0000")];
	time_t whence;

	if (rt == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	whence = rt->secs;
	strftime(tbuf, sizeof(tbuf), "%FT%T%z", localtime(&whence));
	if (tbstrcpy(&sa, tbuf)) {
		tbstrfree(&sa);
		return "error";
	}

	return sa.s;
}

const char *
print_RobinAttributes(const RobinAttributes *a)
{
	static tbstring sa;
	unsigned int u;
	int one = 0;

	if (a == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		goto fail;

	if (a->type) {
		tbstrprintfcat(&sa, "type=%s", robin_type(*a->type));
		one++;
	}

	if (a->acl) {
		tbstrprintfcat(&sa, "%sowner=%s", one++ ? "," : "",
				robin_log_princ(&a->acl->owner));
		tbstrprintfcat(&sa, ",oright=<%s>", print_ROBIN_RIGHT(a->acl->rights));
		tbstrprintfcat(&sa, ",nright=<%s>",
				print_ROBIN_RIGHT(a->acl->nrights));
		tbstrprintfcat(&sa, ",aright=<%s>",
				print_ROBIN_RIGHT(a->acl->arights));

		if (a->acl->list && a->acl->list->len > 0)
			for (u = 0; u < a->acl->list->len; u++)
				tbstrprintfcat(&sa, ",acl:%s=<%s>",
						robin_log_princ(&a->acl->list->val[u].principal),
						print_ROBIN_RIGHT(a->acl->list->val[u].rights));
	}

	if (a->mtime)
		tbstrprintfcat(&sa, "%smtime=%lld", one++ ? "," : "", a->mtime->secs);
	if (a->atime)
		tbstrprintfcat(&sa, "%satime=%lld", one++ ? "," : "", a->atime->secs);
	if (a->ctime)
		tbstrprintfcat(&sa, "%sctime=%lld", one++ ? "," : "", a->ctime->secs);

	if (a->size)
		tbstrprintfcat(&sa, "%ssize=%lld", one++ ? "," : "", *a->size);

	if (a->family) {
		tbstrprintfcat(&sa, "%snlink=%u", one++ ? "," : "", a->family->len);
		for (u = 0; u < a->family->len; u++)
			tbstrprintfcat(&sa, ",name=%.*s",
					(int)a->family->val[u].name.length,
					(char *)a->family->val[u].name.data);
	}

	return sa.s;

fail:
	tbstrfree(&sa);
	return "error";
}

const char *
print_RobinChecksum(const RobinChecksum *sum)
{
	static tbstring sa;
	char *p = NULL;
	char hexc[4];
	uint8_t *h;

	if (sum == NULL) {
		tbstrfree(&sa);
		return "none";
	}

	switch (sum->cksumtype) {
		case RCKSUMTYPE_NONE:	p = "NONE"; break;
		case RCKSUMTYPE_MD5:	p = "MD5"; break;
		case RCKSUMTYPE_SHA1:	p = "SHA1"; break;
		case RCKSUMTYPE_RMD160:	p = "RMD160"; break;
		case RCKSUMTYPE_SHA256:	p = "SHA256"; break;
		case RCKSUMTYPE_SHA384:	p = "SHA384"; break;
		case RCKSUMTYPE_SHA512:	p = "SHA512"; break;
		case RCKSUMTYPE_ROLL32:	p = "ROLL32"; break;
		case RCKSUMTYPE_MD4:	p = "MD4"; break;
		default:				p = "INVALID"; break;
	}

	if (tbstrcpy(&sa, p))
		goto fail;

	if (sum->checksum.length > 0)
		if (tbstrcat(&sa, ":"))
			goto fail;

	for (h = (uint8_t *)sum->checksum.data;
			h < (uint8_t *)sum->checksum.data + sum->checksum.length; h++) {
		snprintf(hexc, sizeof(hexc), "%.2X", *h);
		if (tbstrcat(&sa, hexc))
			goto fail;
	}

	return sa.s;

fail:
	tbstrfree(&sa);
	return "error";
}

const char *
print_RobinHost(const RobinHost *host)
{
	static tbstring sa;

	if (host == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%s", host->hostname ? host->hostname : "unknown")) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinHosts(const RobinHosts *hosts)
{
	static tbstring sa;
	unsigned int u;

	if (hosts == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < hosts->len; u++)
		if (tbstrprintfcat(&sa, "%s%s", u == 0 ? "" : ", ",
					print_RobinHost(&hosts->val[u]))) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_RobinToken(const RobinToken *token)
{
	static tbstring sa;

	if (token == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%u.%u.%u.%u/%d:%s@%s:%s@%s:%.*s",
				token->data.hdl.vol, token->data.hdl.ino, token->data.hdl.gen,
				token->data.hdl.ver, token->data.prefix,
				token->data.signator.name, token->data.signator.cell,
				token->data.principal.name, token->data.principal.cell,
				token->data.partition ? (int)token->data.partition->length : 0,
				token->data.partition ? (char *)token->data.partition->data :
				"")) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinTokens(const RobinTokens *tokens)
{
	static tbstring sa;
	unsigned int u;

	if (tokens == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < tokens->len; u++)
		if (tbstrprintfcat(&sa, "%s%s", u == 0 ? "" : ", ",
					print_RobinToken(&tokens->val[u]))) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_RobinRightsList(const RobinRightsList *rights)
{
	static tbstring sa;
	unsigned int u;

	if (rights == NULL || rights->len == 0) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < rights->len; u++)
		if (tbstrprintfcat(&sa, "%sacl:%s=<%s>", u == 0 ? "" : ",",
					robin_log_princ(&rights->val[u].principal),
					print_ROBIN_RIGHT(rights->val[u].rights))) {
			tbstrfree(&sa);
			return "error";
		}
	return sa.s;
}

const char *
print_RobinHandle(const RobinHandle *hdl)
{
	static tbstring sa;

	if (hdl == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%u.%u.%u.%u",
				hdl->vol, hdl->ino, hdl->gen, hdl->ver)) {
		tbstrfree(&sa);
		return "error";
	}

	return sa.s;
}

const char *
print_RobinDirentry(const RobinDirentry *rd)
{
	static tbstring sa;

	if (rd == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "%u.%u.%u.%u:%s:\"%.*s\"",
				rd->hdl.vol, rd->hdl.ino, rd->hdl.gen, rd->hdl.ver,
				robin_type(rd->type),
				(int)rd->name.length, (char *)rd->name.data)) {
		tbstrfree(&sa);
		return "error";
	}

	return sa.s;
}

const char *
print_RobinDirentries(const RobinDirentries *ents)
{
	static tbstring sa;
	unsigned int u;

	if (ents == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < ents ->len; u++)
		if (tbstrprintfcat(&sa, "%s%s", u == 0 ? "" : ", ",
					print_RobinDirentry(&ents->val[u]))) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_RobinNodeFlags(RobinNodeFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinNodeFlags2int(flags),
					asn1_RobinNodeFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinConFlags(RobinConFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinConFlags2int(flags),
					asn1_RobinConFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_ROBIN_LOCKTYPE(ROBIN_LOCKTYPE flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(ROBIN_LOCKTYPE2int(flags),
					asn1_ROBIN_LOCKTYPE_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_ROBIN_LOCKTYPE_2(ROBIN_LOCKTYPE flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(ROBIN_LOCKTYPE2int(flags),
					asn1_ROBIN_LOCKTYPE_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_ROBIN_RIGHT(ROBIN_RIGHT flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(ROBIN_RIGHT2int(flags),
					asn1_ROBIN_RIGHT_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinTransFlags(RobinTransFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinTransFlags2int(flags),
					asn1_RobinTransFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinGroupFlags(RobinGroupFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinGroupFlags2int(flags),
					asn1_RobinGroupFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinGroupRight(RobinGroupRight flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinGroupRight2int(flags),
					asn1_RobinGroupRight_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinGroupRight_2(RobinGroupRight flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinGroupRight2int(flags),
					asn1_RobinGroupRight_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinDiskFlags(RobinDiskFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinDiskFlags2int(flags),
					asn1_RobinDiskFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinRouterFlags(RobinRouterFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinRouterFlags2int(flags),
					asn1_RobinRouterFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinData(const RobinData *data)
{
	static tbstring sa;
	char *buf;

	if (data == NULL) {
		tbstrfree(&sa);
		return "\"\"";
	}
	if ((buf = malloc(data->length * 4 + 1)) == NULL) {
		tbstrfree(&sa);
		return "error";
	}
	strvisx(buf, data->data, data->length, VIS_OCTAL);
	if (tbstrprintf(&sa, "\"%s\"", buf)) {
		free(buf);
		tbstrfree(&sa);
		return "error";
	}
	free(buf);
	return sa.s;
}

const char *
print_RobinData_2(const RobinData *data)
{
	static tbstring sa;
	char *buf;

	if (data == NULL) {
		tbstrfree(&sa);
		return "\"\"";
	}
	if ((buf = malloc(data->length * 4 + 1)) == NULL) {
		tbstrfree(&sa);
		return "error";
	}
	strvisx(buf, data->data, data->length, VIS_OCTAL);
	if (tbstrprintf(&sa, "\"%s\"", buf)) {
		free(buf);
		tbstrfree(&sa);
		return "error";
	}
	free(buf);
	return sa.s;
}

const char *
print_RobinEncryptionKey(const RobinEncryptionKey *key)
{
	static tbstring sa;
	char *buf;

	if (key == NULL) {
		tbstrfree(&sa);
		return "none:0";
	}
	krb5_enctype_to_string(NULL, key->keytype, &buf);
	/* print the number of bits in the key */
	if (tbstrprintf(&sa, "%s:%zd", buf, key->keyvalue.length << 3)) {
		free(buf);
		tbstrfree(&sa);
		return "error";
	}
	free(buf);
	return sa.s;
}

const char *
print_ROBIN_CKSUMTYPE(ROBIN_CKSUMTYPE type)
{
	static tbstring sa;
	char *p;

	switch (type) {
		case RCKSUMTYPE_NONE:	p = "NONE"; break;
		case RCKSUMTYPE_MD5:	p = "MD5"; break;
		case RCKSUMTYPE_SHA1:	p = "SHA1"; break;
		case RCKSUMTYPE_RMD160:	p = "RMD160"; break;
		case RCKSUMTYPE_SHA256:	p = "SHA256"; break;
		case RCKSUMTYPE_SHA384:	p = "SHA384"; break;
		case RCKSUMTYPE_SHA512:	p = "SHA512"; break;
		case RCKSUMTYPE_ROLL32:	p = "ROLL32"; break;
		case RCKSUMTYPE_MD4:	p = "MD4"; break;
		default:				p = "INVALID"; break;
	}

	if (tbstrcpy(&sa, p)) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinSyncFlags(RobinSyncFlags flags)
{
	static tbstring sa;
	if (tbstrcpy(&sa, tbox_units(RobinSyncFlags2int(flags),
					asn1_RobinSyncFlags_units()))) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinSyncCommand(const RobinSyncCommand *cmd)
{
	static tbstring sa;
	char *p;

	if (cmd == NULL) {
		tbstrfree(&sa);
		return "none";
	}

	switch (cmd->command) {
		case RSYNC_GETSUMS:	p = "GETSUMS";	break;
		case RSYNC_ADD:		p = "ADD";		break;
		case RSYNC_COPY:	p = "COPY";		break;
		case RSYNC_RUN:		p = "RUN";		break;
		default:			p = "INVALID";	break;
	}
	if (tbstrprintf(&sa, "%s:%lld:%lld:%lld:%zd",
				p, cmd->offset, cmd->length, cmd->other, cmd->data.length)) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}

const char *
print_RobinSyncCommands(const RobinSyncCommands *cmds)
{
	static tbstring sa;
	unsigned int u;

	if (cmds == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrcpy(&sa, ""))
		return "error";
	for (u = 0; u < cmds->len; u++)
		if (tbstrprintfcat(&sa, "%s%s", u == 0 ? "" : ", ",
					print_RobinSyncCommand(&cmds->val[u]))) {
			tbstrfree(&sa);
			return "error";
		}

	return sa.s;
}

const char *
print_RobinLock(const RobinLock *lock)
{
	static tbstring sa;
	
	if (lock == NULL) {
		tbstrfree(&sa);
		return "none";
	}
	if (tbstrprintf(&sa, "<%s>", print_ROBIN_LOCKTYPE_2(lock->type))) {
		tbstrfree(&sa);
		return "error";
	}
	if (lock->expiry)
		if (tbstrprintfcat(&sa, ":%s", print_RobinTime_date_2(lock->expiry))) {
			tbstrfree(&sa);
			return "error";
		}
	if (lock->lower || lock->upper)
		if (tbstrprintfcat(&sa, ":%lld-%lld",
					lock->lower ? *lock->lower : 0,
					lock->upper ? *lock->upper : -1)) {
			tbstrfree(&sa);
			return "error";
		}
	return sa.s;
}

const char *
print_RobinSyncChecksum(const RobinSyncChecksum *sum)
{
	static tbstring sa;

	if (sum == NULL) {
		tbstrfree(&sa);
		return "none";
	}

	if (tbstrprintf(&sa, "%lld:%lld:%lld:%u:%u",
				sum->offset, sum->length, sum->blksiz,
				sum->weaksums.len, sum->hardsums.len)) {
		tbstrfree(&sa);
		return "error";
	}
	return sa.s;
}
