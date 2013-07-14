/* $Gateweaver: robin.h,v 1.97 2007/05/29 17:29:51 cmaxwell Exp $ */
#ifndef ROBIN_H
#define ROBIN_H
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <event.h>
#include <kerberosV/asn1_err.h>
#include <kerberosV/krb5.h>
#include "pigeon_locl.h"
#include "robin_err.h"
#include "robin_asn1.h"

#define ROBIN_PROT_VER	3
#define ROBIN_SUCCESS	0
#define ROBIN_CALLBACK_DONE	0

#define ROBIN_CONNECT_TIMEOUT	600

#define ROBIN_CONFFILE	"/etc/rfs.conf"
#define ROBIN_CONFENV	"ROBIN_CONFFILE"
#define ROBIN_SERVICE	"cell"
#define ROBIN_VOLUME_RESERVE	(1*1024*1024)
#define ROBIN_SOCKBUF_SIZE		65536

#define ROBIN_MAX_PREFIX		96
#define ROBIN_MAX_HANDLE		UINT_MAX

#define ROBIN_LOG_NONE			0x0000
#define ROBIN_LOG_STATE			0x0008
#define ROBIN_LOG_STATE_TIMING	0x0004
#define ROBIN_LOG_PROTO			0x0010
#define ROBIN_LOG_PROTO_DUMP	0x0020
#define ROBIN_LOG_CONNECT		0x0040

#define HANDLECOPY(src, dst) do { \
	(dst)->vol = (src)->vol;	\
	(dst)->ino = (src)->ino;	\
	(dst)->gen = (src)->gen;	\
	(dst)->ver = (src)->ver;	\
} while (0)

/*
 * MD5_DIGEST_LENGTH		= 16
 * SHA_DIGEST_LENGTH		= 20
 * RIPEMD160_DIGEST_LENGTH	= 20
 * SHA256_DIGEST_LENGTH		= 32
 * SHA384_DIGEST_LENGTH		= 48
 * SHA512_DIGEST_LENGTH		= 64
 */
#define RCKSUM_LENGTH	64

struct robin_state;
struct robin_con_connect;
struct robin_con_data;
typedef struct robin_con_data *robin_con;
struct robin_context_data;
typedef struct robin_context_data *robin_context;

/* CALLBACK functions */
typedef void (RCB_CONNECT)(robin_context, robin_con, int, void *);
typedef void (RCB_ACCEPT)(robin_context, robin_con, int, void *);
typedef int (RCB_PROCESS)(robin_context, robin_con,
		ROBIN_MSGTYPE, RobinHeader *, size_t, void *);
typedef void (RCB_SHUTDOWN)(robin_context, robin_con, int, void *);

/*
 * Connection state.  Allocated when connect first called, destroyed once the
 * robin_con is fully connected.  Avoids having to change the arguments in the
 * pigeon library between connect and run.
 */
struct robin_con_connect {
	enum {
		CONNECT_LOOKUP_SRV,		/* looking up the SRV record */
		CONNECT_LOOKUP_A,		/* looking up the A record */
		CONNECT_ING,			/* connect in progress, to the hostindex */
		CONNECT_ED,				/* connected to the hostindex */
		CONNECT_FAIL,			/* major failure */
		CONNECT_TIMEDOUT		/* timed out, dns can reap */
	} state;
	RobinHosts hosts;			/* private host info */
	unsigned int hostindex;		/* host number currently working on */
	unsigned int addrindex;		/* addr number currently working on */
	unsigned int nsqueries;		/* counter of pending queries */
	struct event timer;			/* timeout during connections */
};

typedef struct robin_con_data {
	TAILQ_ENTRY(robin_con_data) entry;
	enum pigeon_mode mode;				/* pigeon service mode */
	struct pigeon *p;					/* pigeon connection handle */
	RobinHost *host;					/* host info to context cellhost */
	uint32_t xid;						/* transaction id counter */
	struct robin_context_data *context;	/* backpointer to the parent context */
	int destroying:1;					/* destruction in progress */
	int cleartext:1;					/* use cleartext sublayer */

	struct robin_con_connect connect;	/* connection state keeper */

	/*
	 * EXTERNAL PROCESSORS - the client processing functions (if required).
	 * Primarily used for servers, these will be called from the ENGINE (if
	 * enabled), or directly from the INTERNAL PROCESSOR.
	 */
	struct {
		RCB_CONNECT *connect;
		RCB_ACCEPT *accept;
		RCB_PROCESS *process;
		RCB_SHUTDOWN *shutdown;
		void *arg;
	} cb;

} robin_con_data;

typedef struct robin_context_data {
	struct et_list *et_list;			/* error code table */
	struct timeval tv_cmdtimeout;		/* default command timeout */
	uint32_t refcount;					/* reference count */

	RobinCell cell;						/* cell name, and host/addr list */
	TAILQ_HEAD(robin_state_tq, robin_state) state;

	/*
	 * ENGINE - the 'second' level processing functions, used to internally
	 * handle state replies.
	 *
	 * defcb handles callbacks to be set as default for new connections
	 */
	struct {
		RCB_CONNECT *connect;			/* engine connect function */
		RCB_ACCEPT *accept;				/* engine accept function */
		RCB_PROCESS *process;			/* engine process function */
		RCB_SHUTDOWN *shutdown;			/* engine shutdown function */
		void *arg;						/* engine private argument */
	} cb, defcb;

	struct {
		robin_con master;				/* master node router connection */
		TAILQ_HEAD(robin_con_data_tq, robin_con_data) list;
		uint16_t port;					/* default connection port */
		uint16_t cleartext:1;			/* use cleartext sublayer */
		time_t timeout;					/* default connection timeout */
		char *username;					/* default username */
		char *servname;					/* default service name */
		char *ccache;					/* default credentials cache */
		enum pigeon_mode connectas;		/* default connection mode */
		int sfd;						/* connect using this socket */
	} con;

} robin_context_data;

/* Callback types */
typedef int (RCB_STATUS)(robin_context, robin_con, ROBIN_STATUS *, void *);

/* MESSAGING callbacks */
typedef int (RCB_GETROOT)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);
typedef int (RCB_GETROUTE)(robin_context, robin_con, ROBIN_STATUSROUTE *, void *);
typedef int (RCB_GETDISK)(robin_context, robin_con, ROBIN_STATUSDISK *, void *);
typedef int (RCB_GETCLIENT)(robin_context, robin_con, ROBIN_STATUSHOST *, void *);
typedef int (RCB_GETOID)(robin_context context, robin_con con, ROBIN_STATUSOID *, void *);
typedef int (RCB_SETOID)(robin_context context, robin_con con, ROBIN_STATUS *, void *);
typedef int (RCB_GETLOCK)(robin_context context, robin_con con, ROBIN_STATUSLOCK *, void *);
typedef int (RCB_GETACTION)(robin_context context, robin_con con, ROBIN_STATUSLOCK *, void *);
typedef int (RCB_GETTRANS)(robin_context context, robin_con con, ROBIN_STATUSLOCK *, void *);

/* CONNECTION callbacks */
typedef int (RCB_PING)(robin_context, robin_con, ROBIN_PONG *, void *);
typedef int (RCB_SETCLIENTID)(robin_context, robin_con, ROBIN_STATUSDATA *, void *);
typedef int (RCB_SETCON)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DISCONNECT)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_REFRESH)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);

/* NODE callbacks */
typedef int (RCB_MKNODE)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_MKSYM)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);
typedef int (RCB_OPEN)(robin_context, robin_con, ROBIN_STATUSLOCK *, void *);
typedef int (RCB_UNLOCK)(robin_context, robin_con, ROBIN_STATUSLOCK *, void *);
typedef int (RCB_GETATTR)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_PUTATTR)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_GETACL)(robin_context, robin_con, ROBIN_STATUSACL *, void *);
typedef int (RCB_PUTACL)(robin_context, robin_con, ROBIN_STATUSACL *, void *);

/* NODE DATA callbacks */
typedef int (RCB_READ)(robin_context, robin_con, ROBIN_STATUSDATA *, void *);
typedef int (RCB_WRITE)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_APPEND)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_TRANS_START)(robin_context, robin_con, ROBIN_STATUSTOKEN *, void *);
typedef int (RCB_TRANS_WRITE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_TRANS_APPEND)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_TRANS_READ)(robin_context, robin_con, ROBIN_STATUSDATA *, void *);
typedef int (RCB_TRANS_FINISH)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_TRANS_ABORT)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_TRANS_SYNC)(robin_context, robin_con, ROBIN_STATUSSYNC *, void *);

/* NODE MANIPULATION callbacks */
typedef int (RCB_NODE_PUT)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_NODE_DEL)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_NODE_COW)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_NODE_SYNC)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_NODE_XFER)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_NODE_SNAP)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);
typedef int (RCB_NODE_GETSUM)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);

/* NAMESPACE callbacks */
typedef int (RCB_LOOKUP)(robin_context, robin_con, ROBIN_STATUSDIRENT *, void *);
typedef int (RCB_READDIR)(robin_context, robin_con, ROBIN_STATUSDIRENT *, void *);
typedef int (RCB_DIRLINK)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_DIRUNLINK)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_DIRRELINK)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_DIRCREATE)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_DIRSYMLINK)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);
typedef int (RCB_DIRRENAME)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DIRHISTGET)(robin_context, robin_con, ROBIN_STATUSDIRENT *, void *);
typedef int (RCB_DIRHISTSET)(robin_context, robin_con, ROBIN_STATUSDIRENT *, void *);

/* GROUP callbacks */
typedef int (RCB_GROUP_CREATE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_GROUP_DELETE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_GROUP_MODIFY)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_GROUP_RENAME)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_GROUP_ADD)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_GROUP_DEL)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_GROUP_GET)(robin_context, robin_con, ROBIN_STATUSGROUP *, void *);
typedef int (RCB_GROUP_PUT)(robin_context, robin_con, ROBIN_STATUSGROUP *, void *);
typedef int (RCB_GROUP_EVAL)(robin_context, robin_con, ROBIN_STATUS *, void *);

/* IHAVE callbacks */
typedef int (RCB_IHAVE_PART)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_VOLUME)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_NODE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_ROUTE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_FINISHED)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_GROUP)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_TRANS)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_WITHDRAW)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_IHAVE_PROTECT)(robin_context, robin_con, ROBIN_STATUS *, void *);

/* VOLUME callbacks */
typedef int (RCB_VOLUME_GETROOT)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);
typedef int (RCB_VOLUME_SETROOT)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_VOLUME_CREATE)(robin_context, robin_con, ROBIN_STATUSHDL *, void *);
typedef int (RCB_VOLUME_MKNODE)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_VOLUME_CHNODE)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_VOLUME_STNODE)(robin_context, robin_con, ROBIN_STATUSINFO *, void *);
typedef int (RCB_VOLUME_RMNODE)(robin_context, robin_con, ROBIN_STATUSHDLSUM *, void *);
typedef int (RCB_VOLUME_SNAPSHOT)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_VOLUME_DIRLINK)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_VOLUME_DIRUNLINK)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_VOLUME_VRNODE)(robin_context, robin_con, ROBIN_STATUSTOKEN *, void *);
typedef int (RCB_VOLUME_VRSIZE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_VOLUME_RACL)(robin_context, robin_con, ROBIN_STATUSACL *, void *);
typedef int (RCB_VOLUME_WACL)(robin_context, robin_con, ROBIN_STATUSACL *, void *);

/* TOKEN callbacks */
typedef int (RCB_TOKEN_VERIFY)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_TOKEN_PUT)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_TOKEN_GET)(robin_context, robin_con, ROBIN_STATUSTOKEN *, void *);
typedef int (RCB_TOKEN_DEL)(robin_context, robin_con, ROBIN_STATUS *, void *);

/* COMPOUND callbacks */
typedef int (RCB_COMPOUND)(robin_context, robin_con, ROBIN_STATUS *, void *);

/* DISK callbacks */
typedef int (RCB_DISK_INITIALIZE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DISK_MODIFY)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DISK_RECOVER)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DISK_BALANCE)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DISK_POWERUP)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_DISK_POWERDOWN)(robin_context, robin_con, ROBIN_STATUS *, void *);

/* PROTECT callbacks */
typedef int (RCB_PROTECT_GET)(robin_context, robin_con, ROBIN_STATUSPROTECT *, void *);
typedef int (RCB_PROTECT_ADD)(robin_context, robin_con, ROBIN_STATUS *, void *);
typedef int (RCB_PROTECT_DEL)(robin_context, robin_con, ROBIN_STATUS *, void *);

/*
 * Storage union for status replies, to avoid overrunning the callback arg
 */
typedef union {
	/* 20 */ ROBIN_STATUS status;
	/* 21 */ ROBIN_STATUSHDL statushdl;
	/* 22 */ ROBIN_STATUSHDLSUM statushdlsum;
	/* 23 */ ROBIN_STATUSROUTE statusroute;
	/* 24 */ ROBIN_STATUSLOCK statuslock;
	/* 25 */ ROBIN_STATUSINFO statusinfo;
	/* 26 */ ROBIN_STATUSACL statusacl;
	/* 27 */ ROBIN_STATUSDATA statusdata;
	/* 28 */ ROBIN_STATUSDIRENT statusdirent;
	/* 29 */ ROBIN_STATUSTOKEN statustoken;
	/* 30 */ ROBIN_STATUSDISK statusdisk;
	/* 31 */ ROBIN_STATUSHOST statushost;
	/* 32 */ ROBIN_STATUSGROUP statusgroup;
	/* 33 */ ROBIN_STATUSOID statusoid;
	/* 34 */ ROBIN_STATUSPROTECT statusprotect;
	/* 35 */ ROBIN_STATUSSYNC statussync;
} ROBIN_STATUS_STORAGE;

#define ROBIN_MSG_STATUS_MAX	ROBIN_MSG_STATUSSYNC

void robin_init(void);
void robin_set_process(robin_context, RCB_PROCESS *, void *);
const char * robin_print_error(robin_context, int);

/* Interface Functions */
int robin_init_context(robin_context *);
void robin_free_context(robin_context);
void robin_shutdown_context(robin_context);
int robin_init_con(robin_context, robin_con *);
int robin_valid_con(robin_context, robin_con);
void robin_free_con(robin_context, robin_con);
void robin_shutdown_con(robin_context, robin_con);
int robin_con_setpigeon(robin_context, robin_con, struct pigeon *);
int robin_con_getpigeon(robin_context, robin_con, struct pigeon **);
int robin_set_hostname(RobinHost *, const char *);
int robin_set_cell(robin_context, const char *);
int robin_set_service(robin_context, const char *);
int robin_set_port(robin_context, int);
int robin_set_cleartext(robin_context, int);
int robin_set_con_cleartext(robin_context, robin_con,
		int, int);
int robin_set_connect_socket(robin_context, int);
int robin_set_ccache(robin_context, const char *);

void robin_set_engine(robin_context,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *,
		RCB_SHUTDOWN *, void *);
void robin_set_default_callbacks(robin_context,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *,
		RCB_SHUTDOWN *, void *);
void robin_set_connectas_client(robin_context);
int robin_set_username(robin_context, const char *);
int robin_server(robin_context, int, robin_con *,
		RCB_CONNECT *, RCB_ACCEPT *, RCB_PROCESS *,
		RCB_SHUTDOWN *, void *);
int robin_set_con_timeout(robin_context, robin_con, time_t);

/* Utility functions */
void robin_set_logging(int);
int robin_sockaddr2hostaddr(const struct sockaddr *, RobinHostAddress *);
int robin_hostaddr2sockaddr(const RobinHostAddress *, struct sockaddr *);
int robin_add_hostaddr(RobinHost *, const struct sockaddr *);
int robin_add_cellhostname(robin_context, const char *);
int robin_get_cellhost(robin_context, const char *, RobinHost **);
int robin_add_hostname(RobinHosts *, const char *);
int robin_get_hostname(const RobinHosts *, const char *);
int robin_get_host(const RobinHosts *, const char *, RobinHost **);
const char * robin_print_hostaddr(const RobinHostAddress *);
int robin_append_hostaddr(RobinHost *, const RobinHostAddress *);
const char * robin_type(ROBIN_TYPE);
const char * robin_type_short(ROBIN_TYPE);
const char * robin_rights(ROBIN_RIGHT);
const char * robin_rights_short(ROBIN_RIGHT);
const char * robin_locktype(ROBIN_LOCKTYPE);
int robin_handlecmp(const RobinHandle *, const RobinHandle *);
int robin_checksumcmp(const RobinChecksum *, const RobinChecksum *);
int robin_checksumcpy(const RobinChecksum *, RobinChecksum *);
const char * robin_print_clientname(robin_con);
const char * robin_print_servername(robin_con);
int robin_filltime(RobinTime *, int64_t, int32_t);
int robin_cmptime(const RobinTime *, const RobinTime *);
int robin_principal(robin_con, RobinPrincipal *);
int robin_principal_other(robin_con, RobinPrincipal *);
void robin_right_setall(ROBIN_RIGHT *);
int robin_principal_compare(const RobinPrincipal *, const RobinPrincipal *);
const char * robin_log_princ(const RobinPrincipal *);
const char * robin_log_checksum(const RobinChecksum *);
int robin_name2princ(robin_context, const char *, RobinPrincipal *);
krb5_cksumtype robin_cksum2krb(ROBIN_CKSUMTYPE);
ROBIN_CKSUMTYPE robin_krb2cksum(krb5_cksumtype);
krb5_cksumtype robin_token2krb(TOKENTYPE);
TOKENTYPE robin_krb2token(krb5_cksumtype);
RobinPrincipal * robin_princdup(const RobinPrincipal *);
RobinHandle * robin_handledup(const RobinHandle *);
int robin_get_conhost(robin_context, robin_con, RobinHost **);

const char * robin_print_msgtype(ROBIN_MSGTYPE);
const char * robin_print_msg(ROBIN_MSGTYPE, const RobinHeader *);
const char * print_RobinDisk(const RobinDisk *);
const char * print_RobinDisks(const RobinDisks *);
const char * print_RobinPrincipal(const RobinPrincipal *);
const char * print_RobinPrincipal_2(const RobinPrincipal *);
const char * print_RobinPrincipals(const RobinPrincipals *);
const char * print_oid(tb_oid);
const char * print_RobinTime_delta(const RobinTime *);
const char * print_RobinTime_date(const RobinTime *);
const char * print_RobinTime_date_2(const RobinTime *);
const char * print_RobinAttributes(const RobinAttributes *);
const char * print_RobinChecksum(const RobinChecksum *);
const char * print_RobinHost(const RobinHost *);
const char * print_RobinHosts(const RobinHosts *);
const char * print_RobinToken(const RobinToken *);
const char * print_RobinTokens(const RobinTokens *);
const char * print_RobinRightsList(const RobinRightsList *);
const char * print_RobinHandle(const RobinHandle *);
const char * print_RobinDirentry(const RobinDirentry *);
const char * print_RobinDirentries(const RobinDirentries *);
const char * print_RobinNodeFlags(RobinNodeFlags);
const char * print_RobinConFlags(RobinConFlags);
const char * print_ROBIN_LOCKTYPE(ROBIN_LOCKTYPE);
const char * print_ROBIN_LOCKTYPE_2(ROBIN_LOCKTYPE);
const char * print_ROBIN_RIGHT(ROBIN_RIGHT);
const char * print_RobinTransFlags(RobinTransFlags);
const char * print_RobinGroupFlags(RobinGroupFlags);
const char * print_RobinGroupRight(RobinGroupRight);
const char * print_RobinGroupRight_2(RobinGroupRight);
const char * print_RobinDiskFlags(RobinDiskFlags);
const char * print_RobinRouterFlags(RobinRouterFlags);
const char * print_RobinData(const RobinData *);
const char * print_RobinData_2(const RobinData *);
const char * print_RobinEncryptionKey(const RobinEncryptionKey *);
const char * print_ROBIN_CKSUMTYPE(ROBIN_CKSUMTYPE);
const char * print_RobinSyncCommand(const RobinSyncCommand *);
const char * print_RobinSyncCommands(const RobinSyncCommands *);
const char * print_RobinLock(const RobinLock *);
const char * print_RobinSyncFlags(RobinSyncFlags flags);
const char * print_RobinSyncChecksum(const RobinSyncChecksum *);

/* Protocol operations */
void robin_header(robin_context, robin_con, RobinHeader *);

#include "robin_api_msg.h"
#include "robin_api_host.h"
#include "robin_api_user.h"

#endif
