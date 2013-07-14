/* $Gateweaver$ */
/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_MSG_H
#define ROBIN_API_MSG_H
#include "robin.h"

int robin_getroot_api(robin_context, robin_con, const RobinHost *,
		RCB_GETROOT *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */);

int robin_getroute_api(robin_context, robin_con, const RobinHost *,
		RCB_GETROUTE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */);

int robin_getdisk_api(robin_context, robin_con, const RobinHost *,
		RCB_GETDISK *, void *,
		const RobinPrincipal *,
		const RobinDisks *	/* SEQUENCEOF */);

int robin_getclient_api(robin_context, robin_con, const RobinHost *,
		RCB_GETCLIENT *, void *,
		const RobinPrincipal *,
		const RobinDisks *	/* SEQUENCEOF */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_getoid_api(robin_context, robin_con, const RobinHost *,
		RCB_GETOID *, void *,
		const RobinPrincipal *,
		tb_oid	/* OID */);

int robin_setoid_api(robin_context, robin_con, const RobinHost *,
		RCB_SETOID *, void *,
		const RobinPrincipal *,
		tb_oid	/* OID */);

int robin_getlock_api(robin_context, robin_con, const RobinHost *,
		RCB_GETLOCK *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_getaction_api(robin_context, robin_con, const RobinHost *,
		RCB_GETACTION *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_gettrans_api(robin_context, robin_con, const RobinHost *,
		RCB_GETTRANS *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_ping_api(robin_context, robin_con, const RobinHost *,
		RCB_PING *, void *,
		const RobinPrincipal *);

int robin_pong_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number);

int robin_setclientid_api(robin_context, robin_con, const RobinHost *,
		RCB_SETCLIENTID *, void *,
		const RobinPrincipal *,
		const unsigned char *, size_t,
		const unsigned char *, size_t,
		const RobinEncryptionKey *	/* SEQUENCE */);

int robin_setcon_api(robin_context, robin_con, const RobinHost *,
		RCB_SETCON *, void *,
		const RobinPrincipal *,
		const RobinConFlags *	/* BITSTRING */,
		const RobinHostAddress *	/* SEQUENCE */,
		const RobinServerPrefs *	/* SEQUENCEOF */);

int robin_disconnect_api(robin_context, robin_con, const RobinHost *,
		RCB_DISCONNECT *, void *,
		const RobinPrincipal *,
		const RobinConFlags *	/* BITSTRING */,
		const RobinTime *	/* SEQUENCE */);

int robin_refresh_api(robin_context, robin_con, const RobinHost *,
		RCB_REFRESH *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */);

int robin_status_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number);

int robin_statushdl_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinHandle *	/* SEQUENCE */,
		const RobinLock *	/* SEQUENCE */);

int robin_statushdlsum_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinHandle *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinLock *	/* SEQUENCE */);

int robin_statusroute_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		ROBIN_ROUTETYPE	/* int32_t */,
		ROBIN_TYPE	/* int32_t */,
		const RobinRouterFlags *	/* BITSTRING */,
		int32_t	/* int32_t */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const RobinTime *	/* SEQUENCE */);

int robin_statuslock_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinLock *	/* SEQUENCE */,
		const RobinHosts *	/* SEQUENCEOF */,
		const RobinTokens *	/* SEQUENCEOF */);

int robin_statusinfo_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinLock *	/* SEQUENCE */);

int robin_statusacl_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinLock *	/* SEQUENCE */);

int robin_statusdata_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const unsigned char *, size_t);

int robin_statusdirent_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinDirentries *	/* SEQUENCEOF */,
		const RobinLock *	/* SEQUENCE */);

int robin_statustoken_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinToken *	/* SEQUENCE */);

int robin_statusdisk_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinDisk *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinTime *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_statushost_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinHost *	/* SEQUENCE */,
		const unsigned char *, size_t,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_statusgroup_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinGroupRight *	/* BITSTRING */,
		const RobinGroupRight *	/* BITSTRING */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_statusoid_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const unsigned char *, size_t);

int robin_statusprotect_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_statussync_reply(robin_context, robin_con, uint32_t,
		enum rbn_error_number,
		const RobinSyncChecksum *	/* SEQUENCE */);

int robin_mknode_api(robin_context, robin_con, const RobinHost *,
		RCB_MKNODE *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */);

int robin_mksym_api(robin_context, robin_con, const RobinHost *,
		RCB_MKSYM *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */);

int robin_open_api(robin_context, robin_con, const RobinHost *,
		RCB_OPEN *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinDisk *	/* SEQUENCE */);

int robin_unlock_api(robin_context, robin_con, const RobinHost *,
		RCB_UNLOCK *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *	/* BITSTRING */,
		const RobinTime *	/* SEQUENCE */);

int robin_getattr_api(robin_context, robin_con, const RobinHost *,
		RCB_GETATTR *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_putattr_api(robin_context, robin_con, const RobinHost *,
		RCB_PUTATTR *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_getacl_api(robin_context, robin_con, const RobinHost *,
		RCB_GETACL *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_putacl_api(robin_context, robin_con, const RobinHost *,
		RCB_PUTACL *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */);

int robin_read_api(robin_context, robin_con, const RobinHost *,
		RCB_READ *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_write_api(robin_context, robin_con, const RobinHost *,
		RCB_WRITE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_append_api(robin_context, robin_con, const RobinHost *,
		RCB_APPEND *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const unsigned char *, size_t,
		const RobinToken *	/* SEQUENCE */);

int robin_trans_start_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_START *, void *,
		const RobinPrincipal *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_trans_write_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_WRITE *, void *,
		const RobinPrincipal *,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t);

int robin_trans_append_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_APPEND *, void *,
		const RobinPrincipal *,
		const RobinToken *	/* SEQUENCE */,
		const unsigned char *, size_t);

int robin_trans_read_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_READ *, void *,
		const RobinPrincipal *,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */);

int robin_trans_finish_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_FINISH *, void *,
		const RobinPrincipal *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_trans_abort_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_ABORT *, void *,
		const RobinPrincipal *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const unsigned char *, size_t);

int robin_trans_sync_api(robin_context, robin_con, const RobinHost *,
		RCB_TRANS_SYNC *, void *,
		const RobinPrincipal *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinSyncFlags *	/* BITSTRING */,
		ROBIN_CKSUMTYPE	/* int32_t */,
		const RobinSyncCommands *	/* SEQUENCEOF */);

int robin_node_put_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_PUT *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int64_t	/* int64_t */,
		const RobinChecksum *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_del_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_DEL *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_cow_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_COW *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_sync_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_SYNC *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_xfer_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_XFER *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_snap_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_SNAP *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_node_getsum_api(robin_context, robin_con, const RobinHost *,
		RCB_NODE_GETSUM *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_CKSUMTYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_lookup_api(robin_context, robin_con, const RobinHost *,
		RCB_LOOKUP *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_readdir_api(robin_context, robin_con, const RobinHost *,
		RCB_READDIR *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const int32_t *	/* int32_t */,
		const RobinDirentry *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirlink_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRLINK *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirunlink_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRUNLINK *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirrelink_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRRELINK *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		ROBIN_TYPE	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dircreate_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRCREATE *, void *,
		const RobinPrincipal *,
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

int robin_dirsymlink_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRSYMLINK *, void *,
		const RobinPrincipal *,
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

int robin_dirrename_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRRENAME *, void *,
		const RobinPrincipal *,
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

int robin_dirhistget_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRHISTGET *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_dirhistset_api(robin_context, robin_con, const RobinHost *,
		RCB_DIRHISTSET *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		int32_t	/* int32_t */,
		const RobinDisk *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_group_create_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_CREATE *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_delete_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_DELETE *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_modify_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_MODIFY *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinGroupRight *	/* BITSTRING */,
		const RobinGroupRight *	/* BITSTRING */);

int robin_group_rename_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_RENAME *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_add_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_ADD *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_del_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_DEL *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_get_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_GET *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_group_put_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_PUT *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipals *	/* SEQUENCEOF */);

int robin_group_eval_api(robin_context, robin_con, const RobinHost *,
		RCB_GROUP_EVAL *, void *,
		const RobinPrincipal *,
		const RobinPrincipal *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_ihave_part_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_PART *, void *,
		const RobinPrincipal *,
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

int robin_ihave_volume_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_VOLUME *, void *,
		const RobinPrincipal *,
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

int robin_ihave_node_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_NODE *, void *,
		const RobinPrincipal *,
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

int robin_ihave_route_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_ROUTE *, void *,
		const RobinPrincipal *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */,
		int32_t	/* int32_t */);

int robin_ihave_finished_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_FINISHED *, void *,
		const RobinPrincipal *,
		const RobinRouterFlags *	/* BITSTRING */);

int robin_ihave_group_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_GROUP *, void *,
		const RobinPrincipal *,
		const RobinGroupFlags *	/* BITSTRING */);

int robin_ihave_trans_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_TRANS *, void *,
		const RobinPrincipal *,
		const RobinTransFlags *	/* BITSTRING */,
		const RobinToken *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		int64_t	/* int64_t */,
		const unsigned char *, size_t);

int robin_ihave_withdraw_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_WITHDRAW *, void *,
		const RobinPrincipal *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		ROBIN_TYPE	/* int32_t */,
		int32_t	/* int32_t */);

int robin_ihave_protect_api(robin_context, robin_con, const RobinHost *,
		RCB_IHAVE_PROTECT *, void *,
		const RobinPrincipal *,
		const RobinRouterFlags *	/* BITSTRING */,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_volume_getroot_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_GETROOT *, void *,
		const RobinPrincipal *,
		const RobinNodeFlags *	/* BITSTRING */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_setroot_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_SETROOT *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_create_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_CREATE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinQuota *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_volume_mknode_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_MKNODE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_volume_chnode_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_CHNODE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinAttributes *	/* SEQUENCE */,
		const RobinChecksum *	/* SEQUENCE */);

int robin_volume_stnode_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_STNODE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_rmnode_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_RMNODE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_snapshot_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_SNAPSHOT *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */);

int robin_volume_dirlink_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_DIRLINK *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_dirunlink_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_DIRUNLINK *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinFilename *	/* OCTETSTRING */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_vrnode_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_VRNODE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_vrsize_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_VRSIZE *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		int64_t	/* int64_t */,
		const RobinToken *	/* SEQUENCE */);

int robin_volume_racl_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_RACL *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinPrincipal *	/* SEQUENCE */);

int robin_volume_wacl_api(robin_context, robin_con, const RobinHost *,
		RCB_VOLUME_WACL *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinHandle *	/* SEQUENCE */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */,
		const RobinRightsList *	/* SEQUENCEOF */);

int robin_token_verify_api(robin_context, robin_con, const RobinHost *,
		RCB_TOKEN_VERIFY *, void *,
		const RobinPrincipal *,
		const RobinToken *	/* SEQUENCE */);

int robin_token_put_api(robin_context, robin_con, const RobinHost *,
		RCB_TOKEN_PUT *, void *,
		const RobinPrincipal *,
		const RobinToken *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_token_get_api(robin_context, robin_con, const RobinHost *,
		RCB_TOKEN_GET *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_token_del_api(robin_context, robin_con, const RobinHost *,
		RCB_TOKEN_DEL *, void *,
		const RobinPrincipal *,
		const RobinHandle *	/* SEQUENCE */,
		const RobinDisk *	/* SEQUENCE */);

int robin_compound_api(robin_context, robin_con, const RobinHost *,
		RCB_COMPOUND *, void *,
		const RobinPrincipal *);

int robin_disk_initialize_api(robin_context, robin_con, const RobinHost *,
		RCB_DISK_INITIALIZE *, void *,
		const RobinPrincipal *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_modify_api(robin_context, robin_con, const RobinHost *,
		RCB_DISK_MODIFY *, void *,
		const RobinPrincipal *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_recover_api(robin_context, robin_con, const RobinHost *,
		RCB_DISK_RECOVER *, void *,
		const RobinPrincipal *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_balance_api(robin_context, robin_con, const RobinHost *,
		RCB_DISK_BALANCE *, void *,
		const RobinPrincipal *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */,
		const RobinDiskTarget *	/* SEQUENCE */);

int robin_disk_powerup_api(robin_context, robin_con, const RobinHost *,
		RCB_DISK_POWERUP *, void *,
		const RobinPrincipal *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_disk_powerdown_api(robin_context, robin_con, const RobinHost *,
		RCB_DISK_POWERDOWN *, void *,
		const RobinPrincipal *,
		const RobinDisk *	/* SEQUENCE */,
		const RobinDiskFlags *	/* BITSTRING */);

int robin_protect_get_api(robin_context, robin_con, const RobinHost *,
		RCB_PROTECT_GET *, void *,
		const RobinPrincipal *,
		const RobinProtectSource *	/* SEQUENCE */);

int robin_protect_add_api(robin_context, robin_con, const RobinHost *,
		RCB_PROTECT_ADD *, void *,
		const RobinPrincipal *,
		const RobinProtectNodes *	/* SEQUENCEOF */);

int robin_protect_del_api(robin_context, robin_con, const RobinHost *,
		RCB_PROTECT_DEL *, void *,
		const RobinPrincipal *,
		const RobinProtectNodes *	/* SEQUENCEOF */);

#endif
