/* $Gateweaver$ */
/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_HOST_H
#define ROBIN_API_HOST_H
#include "robin.h"

int robin_getroot_host(robin_context, const RobinHost *,
		RCB_GETROOT *, void *,
		const RobinNodeFlags *	/* BITSTRING */);

int robin_getroute_host(robin_context, const RobinHost *,
		RCB_GETROUTE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */);

int robin_getdisk_host(robin_context, const RobinHost *,
		RCB_GETDISK *, void *,
		const RobinDisks *	/* SEQUENCEOF */);

int robin_getclient_host(robin_context, const RobinHost *,
		RCB_GETCLIENT *, void *,
		const RobinDisks *	/* SEQUENCEOF */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_getoid_host(robin_context, const RobinHost *,
		RCB_GETOID *, void *,
		tb_oid	/* OID */);

int robin_setoid_host(robin_context, const RobinHost *,
		RCB_SETOID *, void *,
		tb_oid	/* OID */);

int robin_getlock_host(robin_context, const RobinHost *,
		RCB_GETLOCK *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_getaction_host(robin_context, const RobinHost *,
		RCB_GETACTION *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_gettrans_host(robin_context, const RobinHost *,
		RCB_GETTRANS *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_ping_host(robin_context, const RobinHost *,
		RCB_PING *, void *);

int robin_setclientid_host(robin_context, const RobinHost *,
		RCB_SETCLIENTID *, void *,
		const unsigned char *, size_t,
		const unsigned char *, size_t,
		const RobinEncryptionKey *	/* SEQUENCE */);

int robin_setcon_host(robin_context, const RobinHost *,
		RCB_SETCON *, void *,
		const RobinConFlags *	/* BITSTRING */,
		const RobinHostAddress *	/* SEQUENCE */,
		const RobinServerPrefs *	/* SEQUENCEOF */);

int robin_disconnect_host(robin_context, const RobinHost *,
		RCB_DISCONNECT *, void *,
		const RobinConFlags *	/* BITSTRING */,
		const RobinTime *	/* SEQUENCE */);

int robin_refresh_host(robin_context, const RobinHost *,
		RCB_REFRESH *, void *,
		const RobinHandle *	/* SEQUENCE */);

int robin_mknode_host(robin_context, const RobinHost *,
		RCB_MKNODE *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */);

int robin_mksym_host(robin_context, const RobinHost *,
		RCB_MKSYM *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */);

int robin_open_host(robin_context, const RobinHost *,
		RCB_OPEN *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinDisk *	/* SEQUENCE */);

int robin_unlock_host(robin_context, const RobinHost *,
		RCB_UNLOCK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinTime *	/* SEQUENCE */);

int robin_getattr_host(robin_context, const RobinHost *,
		RCB_GETATTR *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_putattr_host(robin_context, const RobinHost *,
		RCB_PUTATTR *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_getacl_host(robin_context, const RobinHost *,
		RCB_GETACL *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_putacl_host(robin_context, const RobinHost *,
		RCB_PUTACL *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */);

int robin_read_host(robin_context, const RobinHost *,
		RCB_READ *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_write_host(robin_context, const RobinHost *,
		RCB_WRITE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_append_host(robin_context, const RobinHost *,
		RCB_APPEND *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const unsigned char *, size_t,
		const RobinToken *	/* SEQUENCE */);

int robin_trans_start_host(robin_context, const RobinHost *,
		RCB_TRANS_START *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_trans_write_host(robin_context, const RobinHost *,
		RCB_TRANS_WRITE *, void *,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t);

int robin_trans_append_host(robin_context, const RobinHost *,
		RCB_TRANS_APPEND *, void *,
		const RobinToken *	/* SEQUENCE */,
		const unsigned char *, size_t);

int robin_trans_read_host(robin_context, const RobinHost *,
		RCB_TRANS_READ *, void *,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */);

int robin_trans_finish_host(robin_context, const RobinHost *,
		RCB_TRANS_FINISH *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_trans_abort_host(robin_context, const RobinHost *,
		RCB_TRANS_ABORT *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const unsigned char *, size_t);

int robin_trans_sync_host(robin_context, const RobinHost *,
		RCB_TRANS_SYNC *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinSyncFlags *	/* BITSTRING */,
		ROBIN_CKSUMTYPE	/* int32_t */,
		const RobinSyncCommands *	/* SEQUENCEOF */);

int robin_node_put_host(robin_context, const RobinHost *,
		RCB_NODE_PUT *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int64_t	/* int64_t */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_del_host(robin_context, const RobinHost *,
		RCB_NODE_DEL *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_cow_host(robin_context, const RobinHost *,
		RCB_NODE_COW *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_sync_host(robin_context, const RobinHost *,
		RCB_NODE_SYNC *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_xfer_host(robin_context, const RobinHost *,
		RCB_NODE_XFER *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_snap_host(robin_context, const RobinHost *,
		RCB_NODE_SNAP *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_getsum_host(robin_context, const RobinHost *,
		RCB_NODE_GETSUM *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_CKSUMTYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_lookup_host(robin_context, const RobinHost *,
		RCB_LOOKUP *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_readdir_host(robin_context, const RobinHost *,
		RCB_READDIR *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const int32_t *	/* int32_t */,
		const RobinDirentry *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirlink_host(robin_context, const RobinHost *,
		RCB_DIRLINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirunlink_host(robin_context, const RobinHost *,
		RCB_DIRUNLINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirrelink_host(robin_context, const RobinHost *,
		RCB_DIRRELINK *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dircreate_host(robin_context, const RobinHost *,
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

int robin_dirsymlink_host(robin_context, const RobinHost *,
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

int robin_dirrename_host(robin_context, const RobinHost *,
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

int robin_dirhistget_host(robin_context, const RobinHost *,
		RCB_DIRHISTGET *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirhistset_host(robin_context, const RobinHost *,
		RCB_DIRHISTSET *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		int32_t	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_group_create_host(robin_context, const RobinHost *,
		RCB_GROUP_CREATE *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_delete_host(robin_context, const RobinHost *,
		RCB_GROUP_DELETE *, void *,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_modify_host(robin_context, const RobinHost *,
		RCB_GROUP_MODIFY *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinGroupRight *	/* BITSTRING */,
		const RobinGroupRight *	/* BITSTRING */);

int robin_group_rename_host(robin_context, const RobinHost *,
		RCB_GROUP_RENAME *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_add_host(robin_context, const RobinHost *,
		RCB_GROUP_ADD *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_del_host(robin_context, const RobinHost *,
		RCB_GROUP_DEL *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_get_host(robin_context, const RobinHost *,
		RCB_GROUP_GET *, void *,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_put_host(robin_context, const RobinHost *,
		RCB_GROUP_PUT *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_group_eval_host(robin_context, const RobinHost *,
		RCB_GROUP_EVAL *, void *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_ihave_part_host(robin_context, const RobinHost *,
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

int robin_ihave_volume_host(robin_context, const RobinHost *,
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

int robin_ihave_node_host(robin_context, const RobinHost *,
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

int robin_ihave_route_host(robin_context, const RobinHost *,
		RCB_IHAVE_ROUTE *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */);

int robin_ihave_finished_host(robin_context, const RobinHost *,
		RCB_IHAVE_FINISHED *, void *,
		const RobinRouterFlags *	/* BITSTRING */);

int robin_ihave_group_host(robin_context, const RobinHost *,
		RCB_IHAVE_GROUP *, void *,
		const RobinGroupFlags *	/* BITSTRING */);

int robin_ihave_trans_host(robin_context, const RobinHost *,
		RCB_IHAVE_TRANS *, void *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t);

int robin_ihave_withdraw_host(robin_context, const RobinHost *,
		RCB_IHAVE_WITHDRAW *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int32_t	/* int32_t */);

int robin_ihave_protect_host(robin_context, const RobinHost *,
		RCB_IHAVE_PROTECT *, void *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_volume_getroot_host(robin_context, const RobinHost *,
		RCB_VOLUME_GETROOT *, void *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_setroot_host(robin_context, const RobinHost *,
		RCB_VOLUME_SETROOT *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_create_host(robin_context, const RobinHost *,
		RCB_VOLUME_CREATE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinQuota *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_volume_mknode_host(robin_context, const RobinHost *,
		RCB_VOLUME_MKNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_volume_chnode_host(robin_context, const RobinHost *,
		RCB_VOLUME_CHNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_volume_stnode_host(robin_context, const RobinHost *,
		RCB_VOLUME_STNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_rmnode_host(robin_context, const RobinHost *,
		RCB_VOLUME_RMNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_snapshot_host(robin_context, const RobinHost *,
		RCB_VOLUME_SNAPSHOT *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_dirlink_host(robin_context, const RobinHost *,
		RCB_VOLUME_DIRLINK *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_dirunlink_host(robin_context, const RobinHost *,
		RCB_VOLUME_DIRUNLINK *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_vrnode_host(robin_context, const RobinHost *,
		RCB_VOLUME_VRNODE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_vrsize_host(robin_context, const RobinHost *,
		RCB_VOLUME_VRSIZE *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_racl_host(robin_context, const RobinHost *,
		RCB_VOLUME_RACL *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_volume_wacl_host(robin_context, const RobinHost *,
		RCB_VOLUME_WACL *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */);

int robin_token_verify_host(robin_context, const RobinHost *,
		RCB_TOKEN_VERIFY *, void *,
		const RobinToken *	/* SEQUENCE */);

int robin_token_put_host(robin_context, const RobinHost *,
		RCB_TOKEN_PUT *, void *,
		const RobinToken *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_token_get_host(robin_context, const RobinHost *,
		RCB_TOKEN_GET *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_token_del_host(robin_context, const RobinHost *,
		RCB_TOKEN_DEL *, void *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_compound_host(robin_context, const RobinHost *,
		RCB_COMPOUND *, void *);

int robin_disk_initialize_host(robin_context, const RobinHost *,
		RCB_DISK_INITIALIZE *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_modify_host(robin_context, const RobinHost *,
		RCB_DISK_MODIFY *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_recover_host(robin_context, const RobinHost *,
		RCB_DISK_RECOVER *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_balance_host(robin_context, const RobinHost *,
		RCB_DISK_BALANCE *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */,
		const RobinDiskTarget *	/* SEQUENCE */);

int robin_disk_powerup_host(robin_context, const RobinHost *,
		RCB_DISK_POWERUP *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_powerdown_host(robin_context, const RobinHost *,
		RCB_DISK_POWERDOWN *, void *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_protect_get_host(robin_context, const RobinHost *,
		RCB_PROTECT_GET *, void *,
		const RobinProtectSource *	/* SEQUENCE */);

int robin_protect_add_host(robin_context, const RobinHost *,
		RCB_PROTECT_ADD *, void *,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_protect_del_host(robin_context, const RobinHost *,
		RCB_PROTECT_DEL *, void *,
		const RobinProtectNodes *	/* SEQUENCEOF */);

#endif
