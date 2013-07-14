/* $Gateweaver$ */
/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */
#include "robin_locl.h"

int
robin_getroot_host(robin_context context, const RobinHost *host,
		RCB_GETROOT *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */)
{
	return robin_getroot_api(context, NULL, host, callback, arg, NULL,
			flags);
}

int
robin_getroute_host(robin_context context, const RobinHost *host,
		RCB_GETROUTE *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		int32_t limit	/* int32_t */)
{
	return robin_getroute_api(context, NULL, host, callback, arg, NULL,
			hdl,
			prefix,
			limit);
}

int
robin_getdisk_host(robin_context context, const RobinHost *host,
		RCB_GETDISK *callback, void *arg,
		const RobinDisks *disks	/* SEQUENCEOF */)
{
	return robin_getdisk_api(context, NULL, host, callback, arg, NULL,
			disks);
}

int
robin_getclient_host(robin_context context, const RobinHost *host,
		RCB_GETCLIENT *callback, void *arg,
		const RobinDisks *disks	/* SEQUENCEOF */,
		const RobinPrincipals *principals	/* SEQUENCEOF */)
{
	return robin_getclient_api(context, NULL, host, callback, arg, NULL,
			disks,
			principals);
}

int
robin_getoid_host(robin_context context, const RobinHost *host,
		RCB_GETOID *callback, void *arg,
		tb_oid oid	/* OID */)
{
	return robin_getoid_api(context, NULL, host, callback, arg, NULL,
			oid);
}

int
robin_setoid_host(robin_context context, const RobinHost *host,
		RCB_SETOID *callback, void *arg,
		tb_oid oid	/* OID */)
{
	return robin_setoid_api(context, NULL, host, callback, arg, NULL,
			oid);
}

int
robin_getlock_host(robin_context context, const RobinHost *host,
		RCB_GETLOCK *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	return robin_getlock_api(context, NULL, host, callback, arg, NULL,
			hdl,
			prefix,
			principal);
}

int
robin_getaction_host(robin_context context, const RobinHost *host,
		RCB_GETACTION *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	return robin_getaction_api(context, NULL, host, callback, arg, NULL,
			hdl,
			prefix,
			principal);
}

int
robin_gettrans_host(robin_context context, const RobinHost *host,
		RCB_GETTRANS *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		const RobinPrincipal *principal	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	return robin_gettrans_api(context, NULL, host, callback, arg, NULL,
			hdl,
			prefix,
			principal,
			disk);
}

int
robin_ping_host(robin_context context, const RobinHost *host,
		RCB_PING *callback, void *arg)
{
	return robin_ping_api(context, NULL, host, callback, arg, NULL);
}

int
robin_setclientid_host(robin_context context, const RobinHost *host,
		RCB_SETCLIENTID *callback, void *arg,
		const unsigned char *clientid, size_t clientidlen,
		const unsigned char *identity, size_t identitylen,
		const RobinEncryptionKey *verifier	/* SEQUENCE */)
{
	return robin_setclientid_api(context, NULL, host, callback, arg, NULL,
			clientid, clientidlen,
			identity, identitylen,
			verifier);
}

int
robin_setcon_host(robin_context context, const RobinHost *host,
		RCB_SETCON *callback, void *arg,
		const RobinConFlags *flags	/* BITSTRING */,
		const RobinHostAddress *addr	/* SEQUENCE */,
		const RobinServerPrefs *prefs	/* SEQUENCEOF */)
{
	return robin_setcon_api(context, NULL, host, callback, arg, NULL,
			flags,
			addr,
			prefs);
}

int
robin_disconnect_host(robin_context context, const RobinHost *host,
		RCB_DISCONNECT *callback, void *arg,
		const RobinConFlags *flags	/* BITSTRING */,
		const RobinTime *time	/* SEQUENCE */)
{
	return robin_disconnect_api(context, NULL, host, callback, arg, NULL,
			flags,
			time);
}

int
robin_refresh_host(robin_context context, const RobinHost *host,
		RCB_REFRESH *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	return robin_refresh_api(context, NULL, host, callback, arg, NULL,
			hdl);
}

int
robin_mknode_host(robin_context context, const RobinHost *host,
		RCB_MKNODE *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */)
{
	return robin_mknode_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			attr,
			sum,
			lock);
}

int
robin_mksym_host(robin_context context, const RobinHost *host,
		RCB_MKSYM *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinFilename *dest	/* OCTETSTRING */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */)
{
	return robin_mksym_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			attr,
			dest,
			lock);
}

int
robin_open_host(robin_context context, const RobinHost *host,
		RCB_OPEN *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	return robin_open_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			lock,
			disk);
}

int
robin_unlock_host(robin_context context, const RobinHost *host,
		RCB_UNLOCK *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const ROBIN_LOCKTYPE *lock	/* BITSTRING */,
		const RobinTime *expiry	/* SEQUENCE */)
{
	return robin_unlock_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			lock,
			expiry);
}

int
robin_getattr_host(robin_context context, const RobinHost *host,
		RCB_GETATTR *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	return robin_getattr_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl);
}

int
robin_putattr_host(robin_context context, const RobinHost *host,
		RCB_PUTATTR *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	return robin_putattr_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			attr,
			sum);
}

int
robin_getacl_host(robin_context context, const RobinHost *host,
		RCB_GETACL *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	return robin_getacl_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			principal);
}

int
robin_putacl_host(robin_context context, const RobinHost *host,
		RCB_PUTACL *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinRightsList *append	/* SEQUENCEOF */,
		const RobinRightsList *change	/* SEQUENCEOF */,
		const RobinRightsList *delete	/* SEQUENCEOF */)
{
	return robin_putacl_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			append,
			change,
			delete);
}

int
robin_read_host(robin_context context, const RobinHost *host,
		RCB_READ *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_read_api(context, NULL, host, callback, arg, NULL,
			hdl,
			offset,
			length,
			token);
}

int
robin_write_host(robin_context context, const RobinHost *host,
		RCB_WRITE *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		const unsigned char *data, size_t datalen,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_write_api(context, NULL, host, callback, arg, NULL,
			hdl,
			offset,
			length,
			data, datalen,
			sum,
			token);
}

int
robin_append_host(robin_context context, const RobinHost *host,
		RCB_APPEND *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		const unsigned char *data, size_t datalen,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_append_api(context, NULL, host, callback, arg, NULL,
			hdl,
			data, datalen,
			token);
}

int
robin_trans_start_host(robin_context context, const RobinHost *host,
		RCB_TRANS_START *callback, void *arg,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_trans_start_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			offset,
			length,
			token);
}

int
robin_trans_write_host(robin_context context, const RobinHost *host,
		RCB_TRANS_WRITE *callback, void *arg,
		const RobinToken *token	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		const unsigned char *data, size_t datalen)
{
	return robin_trans_write_api(context, NULL, host, callback, arg, NULL,
			token,
			offset,
			data, datalen);
}

int
robin_trans_append_host(robin_context context, const RobinHost *host,
		RCB_TRANS_APPEND *callback, void *arg,
		const RobinToken *token	/* SEQUENCE */,
		const unsigned char *data, size_t datalen)
{
	return robin_trans_append_api(context, NULL, host, callback, arg, NULL,
			token,
			data, datalen);
}

int
robin_trans_read_host(robin_context context, const RobinHost *host,
		RCB_TRANS_READ *callback, void *arg,
		const RobinToken *token	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */)
{
	return robin_trans_read_api(context, NULL, host, callback, arg, NULL,
			token,
			offset,
			length);
}

int
robin_trans_finish_host(robin_context context, const RobinHost *host,
		RCB_TRANS_FINISH *callback, void *arg,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	return robin_trans_finish_api(context, NULL, host, callback, arg, NULL,
			flags,
			token,
			sum);
}

int
robin_trans_abort_host(robin_context context, const RobinHost *host,
		RCB_TRANS_ABORT *callback, void *arg,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const unsigned char *txid, size_t txidlen)
{
	return robin_trans_abort_api(context, NULL, host, callback, arg, NULL,
			flags,
			token,
			txid, txidlen);
}

int
robin_trans_sync_host(robin_context context, const RobinHost *host,
		RCB_TRANS_SYNC *callback, void *arg,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinSyncFlags *sflags	/* BITSTRING */,
		ROBIN_CKSUMTYPE hardsumtype	/* int32_t */,
		const RobinSyncCommands *cmds	/* SEQUENCEOF */)
{
	return robin_trans_sync_api(context, NULL, host, callback, arg, NULL,
			flags,
			token,
			sflags,
			hardsumtype,
			cmds);
}

int
robin_node_put_host(robin_context context, const RobinHost *host,
		RCB_NODE_PUT *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_TYPE type	/* int32_t */,
		int64_t size	/* int64_t */,
		const RobinChecksum *sum	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_put_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			type,
			size,
			sum,
			disk,
			token);
}

int
robin_node_del_host(robin_context context, const RobinHost *host,
		RCB_NODE_DEL *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_del_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			disk,
			token);
}

int
robin_node_cow_host(robin_context context, const RobinHost *host,
		RCB_NODE_COW *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinHandle *nhdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_cow_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			nhdl,
			disk,
			token);
}

int
robin_node_sync_host(robin_context context, const RobinHost *host,
		RCB_NODE_SYNC *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_sync_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			disk,
			token);
}

int
robin_node_xfer_host(robin_context context, const RobinHost *host,
		RCB_NODE_XFER *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_xfer_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			disk,
			token);
}

int
robin_node_snap_host(robin_context context, const RobinHost *host,
		RCB_NODE_SNAP *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinHandle *dhdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_snap_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			dhdl,
			disk,
			token);
}

int
robin_node_getsum_host(robin_context context, const RobinHost *host,
		RCB_NODE_GETSUM *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_CKSUMTYPE cksumtype	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_node_getsum_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			cksumtype,
			disk,
			token);
}

int
robin_lookup_host(robin_context context, const RobinHost *host,
		RCB_LOOKUP *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_lookup_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			name,
			token);
}

int
robin_readdir_host(robin_context context, const RobinHost *host,
		RCB_READDIR *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const int32_t *limit	/* int32_t */,
		const RobinDirentry *last	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_readdir_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			limit,
			last,
			token);
}

int
robin_dirlink_host(robin_context context, const RobinHost *host,
		RCB_DIRLINK *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		ROBIN_TYPE type	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_dirlink_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			hdl,
			name,
			type,
			disk,
			token);
}

int
robin_dirunlink_host(robin_context context, const RobinHost *host,
		RCB_DIRUNLINK *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_dirunlink_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			hdl,
			name,
			disk,
			token);
}

int
robin_dirrelink_host(robin_context context, const RobinHost *host,
		RCB_DIRRELINK *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		ROBIN_TYPE type	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_dirrelink_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			hdl,
			name,
			type,
			disk,
			token);
}

int
robin_dircreate_host(robin_context context, const RobinHost *host,
		RCB_DIRCREATE *callback, void *arg,
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
	return robin_dircreate_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			hdl,
			name,
			attr,
			sum,
			lock,
			disk,
			token);
}

int
robin_dirsymlink_host(robin_context context, const RobinHost *host,
		RCB_DIRSYMLINK *callback, void *arg,
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
	return robin_dirsymlink_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			hdl,
			name,
			attr,
			dest,
			lock,
			disk,
			token);
}

int
robin_dirrename_host(robin_context context, const RobinHost *host,
		RCB_DIRRENAME *callback, void *arg,
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
	return robin_dirrename_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			oldphdl,
			oldname,
			newphdl,
			newname,
			type,
			disk,
			token);
}

int
robin_dirhistget_host(robin_context context, const RobinHost *host,
		RCB_DIRHISTGET *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		int32_t last	/* int32_t */,
		int32_t limit	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_dirhistget_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			name,
			last,
			limit,
			disk,
			token);
}

int
robin_dirhistset_host(robin_context context, const RobinHost *host,
		RCB_DIRHISTSET *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		int32_t limit	/* int32_t */,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_dirhistset_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			phdl,
			name,
			limit,
			disk,
			token);
}

int
robin_group_create_host(robin_context context, const RobinHost *host,
		RCB_GROUP_CREATE *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *owner	/* SEQUENCE */)
{
	return robin_group_create_api(context, NULL, host, callback, arg, NULL,
			group,
			owner);
}

int
robin_group_delete_host(robin_context context, const RobinHost *host,
		RCB_GROUP_DELETE *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */)
{
	return robin_group_delete_api(context, NULL, host, callback, arg, NULL,
			group);
}

int
robin_group_modify_host(robin_context context, const RobinHost *host,
		RCB_GROUP_MODIFY *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *owner	/* SEQUENCE */,
		const RobinGroupRight *public	/* BITSTRING */,
		const RobinGroupRight *private	/* BITSTRING */)
{
	return robin_group_modify_api(context, NULL, host, callback, arg, NULL,
			group,
			owner,
			public,
			private);
}

int
robin_group_rename_host(robin_context context, const RobinHost *host,
		RCB_GROUP_RENAME *callback, void *arg,
		const RobinPrincipal *old_group	/* SEQUENCE */,
		const RobinPrincipal *new_group	/* SEQUENCE */)
{
	return robin_group_rename_api(context, NULL, host, callback, arg, NULL,
			old_group,
			new_group);
}

int
robin_group_add_host(robin_context context, const RobinHost *host,
		RCB_GROUP_ADD *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *user	/* SEQUENCE */)
{
	return robin_group_add_api(context, NULL, host, callback, arg, NULL,
			group,
			user);
}

int
robin_group_del_host(robin_context context, const RobinHost *host,
		RCB_GROUP_DEL *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *user	/* SEQUENCE */)
{
	return robin_group_del_api(context, NULL, host, callback, arg, NULL,
			group,
			user);
}

int
robin_group_get_host(robin_context context, const RobinHost *host,
		RCB_GROUP_GET *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */)
{
	return robin_group_get_api(context, NULL, host, callback, arg, NULL,
			group);
}

int
robin_group_put_host(robin_context context, const RobinHost *host,
		RCB_GROUP_PUT *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipals *users	/* SEQUENCEOF */)
{
	return robin_group_put_api(context, NULL, host, callback, arg, NULL,
			group,
			users);
}

int
robin_group_eval_host(robin_context context, const RobinHost *host,
		RCB_GROUP_EVAL *callback, void *arg,
		const RobinPrincipal *group	/* SEQUENCE */,
		const RobinPrincipal *user	/* SEQUENCE */)
{
	return robin_group_eval_api(context, NULL, host, callback, arg, NULL,
			group,
			user);
}

int
robin_ihave_part_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_PART *callback, void *arg,
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
	return robin_ihave_part_api(context, NULL, host, callback, arg, NULL,
			flags,
			diskflags,
			partition,
			partspace,
			usedspace,
			freespace,
			partnodes,
			usednodes,
			freenodes,
			neednodes,
			maxblock,
			lastmount,
			totperf,
			curperf,
			tokenkey);
}

int
robin_ihave_volume_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_VOLUME *callback, void *arg,
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
	return robin_ihave_volume_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			attr,
			sum,
			token,
			selfname,
			roothdl,
			atime,
			mtime,
			realsize);
}

int
robin_ihave_node_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_NODE *callback, void *arg,
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
	return robin_ihave_node_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			type,
			size,
			sum,
			token,
			atime,
			mtime,
			muser,
			realsize);
}

int
robin_ihave_route_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_ROUTE *callback, void *arg,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinHandle *hdl	/* SEQUENCE */,
		int32_t prefix	/* int32_t */,
		int32_t rtype	/* int32_t */,
		int32_t ttl	/* int32_t */)
{
	return robin_ihave_route_api(context, NULL, host, callback, arg, NULL,
			flags,
			hdl,
			prefix,
			rtype,
			ttl);
}

int
robin_ihave_finished_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_FINISHED *callback, void *arg,
		const RobinRouterFlags *flags	/* BITSTRING */)
{
	return robin_ihave_finished_api(context, NULL, host, callback, arg, NULL,
			flags);
}

int
robin_ihave_group_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_GROUP *callback, void *arg,
		const RobinGroupFlags *flags	/* BITSTRING */)
{
	return robin_ihave_group_api(context, NULL, host, callback, arg, NULL,
			flags);
}

int
robin_ihave_trans_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_TRANS *callback, void *arg,
		const RobinTransFlags *flags	/* BITSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		int64_t offset	/* int64_t */,
		int64_t length	/* int64_t */,
		int64_t append	/* int64_t */,
		const unsigned char *txid, size_t txidlen)
{
	return robin_ihave_trans_api(context, NULL, host, callback, arg, NULL,
			flags,
			token,
			offset,
			length,
			append,
			txid, txidlen);
}

int
robin_ihave_withdraw_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_WITHDRAW *callback, void *arg,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		ROBIN_TYPE type	/* int32_t */,
		int32_t errorcode	/* int32_t */)
{
	return robin_ihave_withdraw_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl,
			hdl,
			type,
			errorcode);
}

int
robin_ihave_protect_host(robin_context context, const RobinHost *host,
		RCB_IHAVE_PROTECT *callback, void *arg,
		const RobinRouterFlags *flags	/* BITSTRING */,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	return robin_ihave_protect_api(context, NULL, host, callback, arg, NULL,
			flags,
			rules);
}

int
robin_volume_getroot_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_GETROOT *callback, void *arg,
		const RobinNodeFlags *flags	/* BITSTRING */,
		const RobinHandle *vhdl	/* SEQUENCE */)
{
	return robin_volume_getroot_api(context, NULL, host, callback, arg, NULL,
			flags,
			vhdl);
}

int
robin_volume_setroot_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_SETROOT *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	return robin_volume_setroot_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl);
}

int
robin_volume_create_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_CREATE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinQuota *quota	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	return robin_volume_create_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			attr,
			quota,
			name,
			token,
			rules);
}

int
robin_volume_mknode_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_MKNODE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	return robin_volume_mknode_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl,
			attr,
			sum);
}

int
robin_volume_chnode_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_CHNODE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinAttributes *attr	/* SEQUENCE */,
		const RobinChecksum *sum	/* SEQUENCE */)
{
	return robin_volume_chnode_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl,
			attr,
			sum);
}

int
robin_volume_stnode_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_STNODE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	return robin_volume_stnode_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl);
}

int
robin_volume_rmnode_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_RMNODE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */)
{
	return robin_volume_rmnode_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl);
}

int
robin_volume_snapshot_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_SNAPSHOT *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *dhdl	/* SEQUENCE */)
{
	return robin_volume_snapshot_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			dhdl);
}

int
robin_volume_dirlink_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_DIRLINK *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_volume_dirlink_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			phdl,
			hdl,
			name,
			token);
}

int
robin_volume_dirunlink_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_DIRUNLINK *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *phdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinFilename *name	/* OCTETSTRING */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_volume_dirunlink_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			phdl,
			hdl,
			name,
			token);
}

int
robin_volume_vrnode_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_VRNODE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_volume_vrnode_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl,
			token);
}

int
robin_volume_vrsize_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_VRSIZE *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		int64_t size	/* int64_t */,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_volume_vrsize_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl,
			size,
			token);
}

int
robin_volume_racl_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_RACL *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinPrincipal *principal	/* SEQUENCE */)
{
	return robin_volume_racl_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl,
			principal);
}

int
robin_volume_wacl_host(robin_context context, const RobinHost *host,
		RCB_VOLUME_WACL *callback, void *arg,
		const RobinHandle *vhdl	/* SEQUENCE */,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinRightsList *append	/* SEQUENCEOF */,
		const RobinRightsList *change	/* SEQUENCEOF */,
		const RobinRightsList *delete	/* SEQUENCEOF */)
{
	return robin_volume_wacl_api(context, NULL, host, callback, arg, NULL,
			vhdl,
			hdl,
			append,
			change,
			delete);
}

int
robin_token_verify_host(robin_context context, const RobinHost *host,
		RCB_TOKEN_VERIFY *callback, void *arg,
		const RobinToken *token	/* SEQUENCE */)
{
	return robin_token_verify_api(context, NULL, host, callback, arg, NULL,
			token);
}

int
robin_token_put_host(robin_context context, const RobinHost *host,
		RCB_TOKEN_PUT *callback, void *arg,
		const RobinToken *token	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	return robin_token_put_api(context, NULL, host, callback, arg, NULL,
			token,
			disk);
}

int
robin_token_get_host(robin_context context, const RobinHost *host,
		RCB_TOKEN_GET *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	return robin_token_get_api(context, NULL, host, callback, arg, NULL,
			hdl,
			disk);
}

int
robin_token_del_host(robin_context context, const RobinHost *host,
		RCB_TOKEN_DEL *callback, void *arg,
		const RobinHandle *hdl	/* SEQUENCE */,
		const RobinDisk *disk	/* SEQUENCE */)
{
	return robin_token_del_api(context, NULL, host, callback, arg, NULL,
			hdl,
			disk);
}

int
robin_compound_host(robin_context context, const RobinHost *host,
		RCB_COMPOUND *callback, void *arg)
{
	return robin_compound_api(context, NULL, host, callback, arg, NULL);
}

int
robin_disk_initialize_host(robin_context context, const RobinHost *host,
		RCB_DISK_INITIALIZE *callback, void *arg,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	return robin_disk_initialize_api(context, NULL, host, callback, arg, NULL,
			disk,
			flags);
}

int
robin_disk_modify_host(robin_context context, const RobinHost *host,
		RCB_DISK_MODIFY *callback, void *arg,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	return robin_disk_modify_api(context, NULL, host, callback, arg, NULL,
			disk,
			flags);
}

int
robin_disk_recover_host(robin_context context, const RobinHost *host,
		RCB_DISK_RECOVER *callback, void *arg,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	return robin_disk_recover_api(context, NULL, host, callback, arg, NULL,
			disk,
			flags);
}

int
robin_disk_balance_host(robin_context context, const RobinHost *host,
		RCB_DISK_BALANCE *callback, void *arg,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */,
		const RobinDiskTarget *target	/* SEQUENCE */)
{
	return robin_disk_balance_api(context, NULL, host, callback, arg, NULL,
			disk,
			flags,
			target);
}

int
robin_disk_powerup_host(robin_context context, const RobinHost *host,
		RCB_DISK_POWERUP *callback, void *arg,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	return robin_disk_powerup_api(context, NULL, host, callback, arg, NULL,
			disk,
			flags);
}

int
robin_disk_powerdown_host(robin_context context, const RobinHost *host,
		RCB_DISK_POWERDOWN *callback, void *arg,
		const RobinDisk *disk	/* SEQUENCE */,
		const RobinDiskFlags *flags	/* BITSTRING */)
{
	return robin_disk_powerdown_api(context, NULL, host, callback, arg, NULL,
			disk,
			flags);
}

int
robin_protect_get_host(robin_context context, const RobinHost *host,
		RCB_PROTECT_GET *callback, void *arg,
		const RobinProtectSource *source	/* SEQUENCE */)
{
	return robin_protect_get_api(context, NULL, host, callback, arg, NULL,
			source);
}

int
robin_protect_add_host(robin_context context, const RobinHost *host,
		RCB_PROTECT_ADD *callback, void *arg,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	return robin_protect_add_api(context, NULL, host, callback, arg, NULL,
			rules);
}

int
robin_protect_del_host(robin_context context, const RobinHost *host,
		RCB_PROTECT_DEL *callback, void *arg,
		const RobinProtectNodes *rules	/* SEQUENCEOF */)
{
	return robin_protect_del_api(context, NULL, host, callback, arg, NULL,
			rules);
}
