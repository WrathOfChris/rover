/* $Gateweaver$ */
/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_USER_H
#define ROBIN_API_USER_H
#include "robin.h"

int robin_getroot(robin_context,
		RCB_GETROOT *, void *,
		const RobinNodeFlags *	/* BITSTRING */);

int robin_getroute(robin_context,
		RCB_GETROUTE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */);

int robin_getdisk(robin_context,
		RCB_GETDISK *, void *,
		const RobinDisks *	/* SEQUENCEOF */);

int robin_getclient(robin_context,
		RCB_GETCLIENT *, void *,
		const RobinDisks *	/* SEQUENCEOF */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_getoid(robin_context,
		RCB_GETOID *, void *,
		tb_oid	/* OID */);

int robin_setoid(robin_context,
		RCB_SETOID *, void *,
		tb_oid	/* OID */);

int robin_getlock(robin_context,
		RCB_GETLOCK *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_getaction(robin_context,
		RCB_GETACTION *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_gettrans(robin_context,
		RCB_GETTRANS *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_ping(robin_context,
		RCB_PING *, void *);

int robin_setclientid(robin_context,
		RCB_SETCLIENTID *, void *,
		const unsigned char *, size_t,
		const unsigned char *, size_t,
		const RobinEncryptionKey *	/* SEQUENCE */);

int robin_setcon(robin_context,
		RCB_SETCON *, void *,
		const RobinConFlags *	/* BITSTRING */,
		const RobinHostAddress *	/* SEQUENCE */,
		const RobinServerPrefs *	/* SEQUENCEOF */);

int robin_disconnect(robin_context,
		RCB_DISCONNECT *, void *,
		const RobinConFlags *	/* BITSTRING */,
		const RobinTime *	/* SEQUENCE */);

int robin_refresh(robin_context,
		RCB_REFRESH *, void *,
		const RobinHandle *	/* SEQUENCE */);

int robin_mknode(robin_context,
		RCB_MKNODE *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */);

int robin_mksym(robin_context,
		RCB_MKSYM *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */);

int robin_open(robin_context,
		RCB_OPEN *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinDisk *	/* SEQUENCE */);

int robin_unlock(robin_context,
		RCB_UNLOCK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinTime *	/* SEQUENCE */);

int robin_getattr(robin_context,
		RCB_GETATTR *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_putattr(robin_context,
		RCB_PUTATTR *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_getacl(robin_context,
		RCB_GETACL *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_putacl(robin_context,
		RCB_PUTACL *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */);

int robin_read(robin_context,
		RCB_READ *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_write(robin_context,
		RCB_WRITE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_append(robin_context,
		RCB_APPEND *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const unsigned char *, size_t,
		const RobinToken *	/* SEQUENCE */);

int robin_trans_start(robin_context,
		RCB_TRANS_START *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_trans_write(robin_context,
		RCB_TRANS_WRITE *, void *,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t);

int robin_trans_append(robin_context,
		RCB_TRANS_APPEND *, void *,
		const RobinToken *	/* SEQUENCE */,
		const unsigned char *, size_t);

int robin_trans_read(robin_context,
		RCB_TRANS_READ *, void *,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */);

int robin_trans_finish(robin_context,
		RCB_TRANS_FINISH *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_trans_abort(robin_context,
		RCB_TRANS_ABORT *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const unsigned char *, size_t);

int robin_trans_sync(robin_context,
		RCB_TRANS_SYNC *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinSyncFlags *	/* BITSTRING */,
		ROBIN_CKSUMTYPE	/* int32_t */,
		const RobinSyncCommands *	/* SEQUENCEOF */);

int robin_node_put(robin_context,
		RCB_NODE_PUT *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int64_t	/* int64_t */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_del(robin_context,
		RCB_NODE_DEL *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_cow(robin_context,
		RCB_NODE_COW *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_sync(robin_context,
		RCB_NODE_SYNC *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_xfer(robin_context,
		RCB_NODE_XFER *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_snap(robin_context,
		RCB_NODE_SNAP *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_getsum(robin_context,
		RCB_NODE_GETSUM *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_CKSUMTYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_lookup(robin_context,
		RCB_LOOKUP *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_readdir(robin_context,
		RCB_READDIR *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const int32_t *	/* int32_t */,
		const RobinDirentry *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirlink(robin_context,
		RCB_DIRLINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirunlink(robin_context,
		RCB_DIRUNLINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirrelink(robin_context,
		RCB_DIRRELINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dircreate(robin_context,
		RCB_DIRCREATE *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirsymlink(robin_context,
		RCB_DIRSYMLINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirrename(robin_context,
		RCB_DIRRENAME *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirhistget(robin_context,
		RCB_DIRHISTGET *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirhistset(robin_context,
		RCB_DIRHISTSET *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		int32_t	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_group_create(robin_context,
		RCB_GROUP_CREATE *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_delete(robin_context,
		RCB_GROUP_DELETE *, void *,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_modify(robin_context,
		RCB_GROUP_MODIFY *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinGroupRight *	/* BITSTRING */,
		const RobinGroupRight *	/* BITSTRING */);

int robin_group_rename(robin_context,
		RCB_GROUP_RENAME *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_add(robin_context,
		RCB_GROUP_ADD *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_del(robin_context,
		RCB_GROUP_DEL *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_get(robin_context,
		RCB_GROUP_GET *, void *,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_put(robin_context,
		RCB_GROUP_PUT *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_group_eval(robin_context,
		RCB_GROUP_EVAL *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_ihave_part(robin_context,
		RCB_IHAVE_PART *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinDiskFlags *	/* BITSTRING */,
		const RobinPartition *	/* OCTETSTRING */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinTime *	/* SEQUENCE */,
		const RobinDiskStats *	/* SEQUENCE */,
		const RobinDiskStats *	/* SEQUENCE */,
		const RobinEncryptionKey *	/* SEQUENCE */);

int robin_ihave_volume(robin_context,
		RCB_IHAVE_VOLUME *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinTime *	/* SEQUENCE */,
		const RobinTime *	/* SEQUENCE */,
		const int64_t *	/* int64_t */);

int robin_ihave_node(robin_context,
		RCB_IHAVE_NODE *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int64_t	/* int64_t */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */,
		const RobinTime *	/* SEQUENCE */,
		const RobinTime *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */,
		const int64_t *	/* int64_t */);

int robin_ihave_route(robin_context,
		RCB_IHAVE_ROUTE *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */);

int robin_ihave_finished(robin_context,
		RCB_IHAVE_FINISHED *, void *,
		const RobinRouterFlags *	/* BITSTRING */);

int robin_ihave_group(robin_context,
		RCB_IHAVE_GROUP *, void *,
		const RobinGroupFlags *	/* BITSTRING */);

int robin_ihave_trans(robin_context,
		RCB_IHAVE_TRANS *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t);

int robin_ihave_withdraw(robin_context,
		RCB_IHAVE_WITHDRAW *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int32_t	/* int32_t */);

int robin_ihave_protect(robin_context,
		RCB_IHAVE_PROTECT *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_volume_getroot(robin_context,
		RCB_VOLUME_GETROOT *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_setroot(robin_context,
		RCB_VOLUME_SETROOT *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_create(robin_context,
		RCB_VOLUME_CREATE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinQuota *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_volume_mknode(robin_context,
		RCB_VOLUME_MKNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_volume_chnode(robin_context,
		RCB_VOLUME_CHNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_volume_stnode(robin_context,
		RCB_VOLUME_STNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_rmnode(robin_context,
		RCB_VOLUME_RMNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_snapshot(robin_context,
		RCB_VOLUME_SNAPSHOT *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_dirlink(robin_context,
		RCB_VOLUME_DIRLINK *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_dirunlink(robin_context,
		RCB_VOLUME_DIRUNLINK *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_vrnode(robin_context,
		RCB_VOLUME_VRNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_vrsize(robin_context,
		RCB_VOLUME_VRSIZE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_racl(robin_context,
		RCB_VOLUME_RACL *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_volume_wacl(robin_context,
		RCB_VOLUME_WACL *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */);

int robin_token_verify(robin_context,
		RCB_TOKEN_VERIFY *, void *,
		const RobinToken *	/* SEQUENCE */);

int robin_token_put(robin_context,
		RCB_TOKEN_PUT *, void *,
		const RobinToken *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_token_get(robin_context,
		RCB_TOKEN_GET *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_token_del(robin_context,
		RCB_TOKEN_DEL *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_compound(robin_context,
		RCB_COMPOUND *, void *);

int robin_disk_initialize(robin_context,
		RCB_DISK_INITIALIZE *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_modify(robin_context,
		RCB_DISK_MODIFY *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_recover(robin_context,
		RCB_DISK_RECOVER *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_balance(robin_context,
		RCB_DISK_BALANCE *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */,
		const RobinDiskTarget *	/* SEQUENCE */);

int robin_disk_powerup(robin_context,
		RCB_DISK_POWERUP *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_powerdown(robin_context,
		RCB_DISK_POWERDOWN *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_protect_get(robin_context,
		RCB_PROTECT_GET *, void *,
		const RobinProtectSource *	/* SEQUENCE */);

int robin_protect_add(robin_context,
		RCB_PROTECT_ADD *, void *,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_protect_del(robin_context,
		RCB_PROTECT_DEL *, void *,
		const RobinProtectNodes *	/* SEQUENCEOF */);

#endif
