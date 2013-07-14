/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */

#ifndef __robin_asn1_h__
#define __robin_asn1_h__

#include <stddef.h>
#include <time.h>

#ifndef __toolbox_asn1_definitions__
#define __toolbox_asn1_definitions__

typedef struct tb_octet_string {
	size_t length;
	void *data;
} tb_octet_string;

typedef char *tb_general_string;

typedef char *tb_utf8_string;

typedef struct tb_oid {
	size_t length;
	unsigned *components;
} tb_oid;

typedef struct tbunits {
	char *name;
	unsigned int mult;
} tbunits;

#define TBASN1_MALLOC_ENCODE(T, B, BL, S, L, R)               \
do {                                                          \
    (BL) = len_##T((S));                                      \
    (B) = malloc((BL));                                       \
    if ((B) == NULL)                                          \
        (R) = ENOMEM;                                         \
    else {                                                    \
        (R) = enc_##T(((unsigned char*)(B)) + (BL) - 1, (BL), \
                         (S), (L));                           \
        if ((R) != 0) {                                       \
            free((B));                                        \
            (B) = NULL;                                       \
        }                                                     \
    }                                                         \
} while (0)

#endif

/*
ROBIN-LOCKTYPE ::= BIT STRING {
  lock_nl(0),
  lock_cr(1),
  lock_cw(2),
  lock_pr(3),
  lock_pw(4),
  lock_ex(5),
  lock_lease(6),
  lock_whole(7),
  lock_range(8),
  lock_avail(9),
  lock_break(10)
}
*/

typedef struct ROBIN_LOCKTYPE {
  uint32_t lock_nl:1;
  uint32_t lock_cr:1;
  uint32_t lock_cw:1;
  uint32_t lock_pr:1;
  uint32_t lock_pw:1;
  uint32_t lock_ex:1;
  uint32_t lock_lease:1;
  uint32_t lock_whole:1;
  uint32_t lock_range:1;
  uint32_t lock_avail:1;
  uint32_t lock_break:1;
} ROBIN_LOCKTYPE;


int enc_ROBIN_LOCKTYPE(unsigned char *, size_t, const ROBIN_LOCKTYPE *, size_t *);
int    dec_ROBIN_LOCKTYPE(const unsigned char *, size_t, ROBIN_LOCKTYPE *, size_t *);
void free_ROBIN_LOCKTYPE  (ROBIN_LOCKTYPE *);
size_t len_ROBIN_LOCKTYPE(const ROBIN_LOCKTYPE *);
int copy_ROBIN_LOCKTYPE(const ROBIN_LOCKTYPE *, ROBIN_LOCKTYPE *);
unsigned ROBIN_LOCKTYPE2int(ROBIN_LOCKTYPE);
ROBIN_LOCKTYPE int2ROBIN_LOCKTYPE(unsigned);
const tbunits * asn1_ROBIN_LOCKTYPE_units(void);

/*
ROBIN-MSGTYPE ::= INTEGER
*/

typedef enum ROBIN_MSGTYPE {
  ROBIN_MSG_GETROOT = 1,
  ROBIN_MSG_GETROUTE = 2,
  ROBIN_MSG_GETDISK = 3,
  ROBIN_MSG_GETCLIENT = 4,
  ROBIN_MSG_GETOID = 5,
  ROBIN_MSG_SETOID = 6,
  ROBIN_MSG_GETLOCK = 7,
  ROBIN_MSG_GETACTION = 8,
  ROBIN_MSG_GETTRANS = 9,
  ROBIN_MSG_PING = 10,
  ROBIN_MSG_PONG = 11,
  ROBIN_MSG_SETCLIENTID = 12,
  ROBIN_MSG_SETCON = 13,
  ROBIN_MSG_DISCONNECT = 14,
  ROBIN_MSG_REFRESH = 15,
  ROBIN_MSG_STATUS = 20,
  ROBIN_MSG_STATUSHDL = 21,
  ROBIN_MSG_STATUSHDLSUM = 22,
  ROBIN_MSG_STATUSROUTE = 23,
  ROBIN_MSG_STATUSLOCK = 24,
  ROBIN_MSG_STATUSINFO = 25,
  ROBIN_MSG_STATUSACL = 26,
  ROBIN_MSG_STATUSDATA = 27,
  ROBIN_MSG_STATUSDIRENT = 28,
  ROBIN_MSG_STATUSTOKEN = 29,
  ROBIN_MSG_STATUSDISK = 30,
  ROBIN_MSG_STATUSHOST = 31,
  ROBIN_MSG_STATUSGROUP = 32,
  ROBIN_MSG_STATUSOID = 33,
  ROBIN_MSG_STATUSPROTECT = 34,
  ROBIN_MSG_STATUSSYNC = 35,
  ROBIN_MSG_MKNODE = 40,
  ROBIN_MSG_MKSYM = 41,
  ROBIN_MSG_OPEN = 42,
  ROBIN_MSG_UNLOCK = 43,
  ROBIN_MSG_GETATTR = 44,
  ROBIN_MSG_PUTATTR = 45,
  ROBIN_MSG_GETACL = 46,
  ROBIN_MSG_PUTACL = 47,
  ROBIN_MSG_READ = 50,
  ROBIN_MSG_WRITE = 51,
  ROBIN_MSG_APPEND = 52,
  ROBIN_MSG_TRANS_START = 53,
  ROBIN_MSG_TRANS_WRITE = 54,
  ROBIN_MSG_TRANS_APPEND = 55,
  ROBIN_MSG_TRANS_READ = 56,
  ROBIN_MSG_TRANS_FINISH = 57,
  ROBIN_MSG_TRANS_ABORT = 58,
  ROBIN_MSG_TRANS_SYNC = 59,
  ROBIN_MSG_NODE_PUT = 60,
  ROBIN_MSG_NODE_DEL = 61,
  ROBIN_MSG_NODE_COW = 62,
  ROBIN_MSG_NODE_SYNC = 63,
  ROBIN_MSG_NODE_XFER = 64,
  ROBIN_MSG_NODE_SNAP = 65,
  ROBIN_MSG_NODE_GETSUM = 66,
  ROBIN_MSG_LOOKUP = 70,
  ROBIN_MSG_READDIR = 71,
  ROBIN_MSG_DIRLINK = 72,
  ROBIN_MSG_DIRUNLINK = 73,
  ROBIN_MSG_DIRRELINK = 74,
  ROBIN_MSG_DIRCREATE = 75,
  ROBIN_MSG_DIRSYMLINK = 76,
  ROBIN_MSG_DIRRENAME = 77,
  ROBIN_MSG_DIRHISTGET = 78,
  ROBIN_MSG_DIRHISTSET = 79,
  ROBIN_MSG_GROUP_CREATE = 80,
  ROBIN_MSG_GROUP_DELETE = 81,
  ROBIN_MSG_GROUP_MODIFY = 82,
  ROBIN_MSG_GROUP_RENAME = 83,
  ROBIN_MSG_GROUP_ADD = 84,
  ROBIN_MSG_GROUP_DEL = 85,
  ROBIN_MSG_GROUP_GET = 86,
  ROBIN_MSG_GROUP_PUT = 87,
  ROBIN_MSG_GROUP_EVAL = 88,
  ROBIN_MSG_IHAVE_PART = 90,
  ROBIN_MSG_IHAVE_VOLUME = 91,
  ROBIN_MSG_IHAVE_NODE = 92,
  ROBIN_MSG_IHAVE_ROUTE = 93,
  ROBIN_MSG_IHAVE_FINISHED = 94,
  ROBIN_MSG_IHAVE_GROUP = 95,
  ROBIN_MSG_IHAVE_TRANS = 96,
  ROBIN_MSG_IHAVE_WITHDRAW = 97,
  ROBIN_MSG_IHAVE_PROTECT = 98,
  ROBIN_MSG_VOLUME_GETROOT = 100,
  ROBIN_MSG_VOLUME_SETROOT = 101,
  ROBIN_MSG_VOLUME_CREATE = 102,
  ROBIN_MSG_VOLUME_MKNODE = 103,
  ROBIN_MSG_VOLUME_CHNODE = 104,
  ROBIN_MSG_VOLUME_STNODE = 105,
  ROBIN_MSG_VOLUME_RMNODE = 106,
  ROBIN_MSG_VOLUME_SNAPSHOT = 107,
  ROBIN_MSG_VOLUME_DIRLINK = 108,
  ROBIN_MSG_VOLUME_DIRUNLINK = 109,
  ROBIN_MSG_VOLUME_VRNODE = 110,
  ROBIN_MSG_VOLUME_VRSIZE = 111,
  ROBIN_MSG_VOLUME_RACL = 112,
  ROBIN_MSG_VOLUME_WACL = 113,
  ROBIN_MSG_TOKEN_VERIFY = 120,
  ROBIN_MSG_TOKEN_PUT = 121,
  ROBIN_MSG_TOKEN_GET = 122,
  ROBIN_MSG_TOKEN_DEL = 123,
  ROBIN_MSG_COMPOUND = 130,
  ROBIN_MSG_DISK_INITIALIZE = 140,
  ROBIN_MSG_DISK_MODIFY = 141,
  ROBIN_MSG_DISK_RECOVER = 142,
  ROBIN_MSG_DISK_BALANCE = 143,
  ROBIN_MSG_DISK_POWERUP = 144,
  ROBIN_MSG_DISK_POWERDOWN = 145,
  ROBIN_MSG_PROTECT_GET = 150,
  ROBIN_MSG_PROTECT_ADD = 151,
  ROBIN_MSG_PROTECT_DEL = 152
} ROBIN_MSGTYPE;

int enc_ROBIN_MSGTYPE(unsigned char *, size_t, const ROBIN_MSGTYPE *, size_t *);
int    dec_ROBIN_MSGTYPE(const unsigned char *, size_t, ROBIN_MSGTYPE *, size_t *);
void free_ROBIN_MSGTYPE  (ROBIN_MSGTYPE *);
size_t len_ROBIN_MSGTYPE(const ROBIN_MSGTYPE *);
int copy_ROBIN_MSGTYPE(const ROBIN_MSGTYPE *, ROBIN_MSGTYPE *);


/*
ROBIN-CKSUMTYPE ::= INTEGER
*/

typedef enum ROBIN_CKSUMTYPE {
  RCKSUMTYPE_NONE = 0,
  RCKSUMTYPE_MD5 = 1,
  RCKSUMTYPE_SHA1 = 2,
  RCKSUMTYPE_RMD160 = 3,
  RCKSUMTYPE_SHA256 = 4,
  RCKSUMTYPE_SHA384 = 5,
  RCKSUMTYPE_SHA512 = 6,
  RCKSUMTYPE_ROLL32 = 7,
  RCKSUMTYPE_MD4 = 8
} ROBIN_CKSUMTYPE;

int enc_ROBIN_CKSUMTYPE(unsigned char *, size_t, const ROBIN_CKSUMTYPE *, size_t *);
int    dec_ROBIN_CKSUMTYPE(const unsigned char *, size_t, ROBIN_CKSUMTYPE *, size_t *);
void free_ROBIN_CKSUMTYPE  (ROBIN_CKSUMTYPE *);
size_t len_ROBIN_CKSUMTYPE(const ROBIN_CKSUMTYPE *);
int copy_ROBIN_CKSUMTYPE(const ROBIN_CKSUMTYPE *, ROBIN_CKSUMTYPE *);


/*
TOKENTYPE ::= INTEGER
*/

typedef enum TOKENTYPE {
  TOKENTYPE_NONE = 0,
  TOKENTYPE_CONFIG = 1,
  TOKENTYPE_FAKE = 2,
  TOKENTYPE_AES128_CTS_HMAC_SHA1_96 = 3,
  TOKENTYPE_AES256_CTS_HMAC_SHA1_96 = 4
} TOKENTYPE;

int enc_TOKENTYPE(unsigned char *, size_t, const TOKENTYPE *, size_t *);
int    dec_TOKENTYPE(const unsigned char *, size_t, TOKENTYPE *, size_t *);
void free_TOKENTYPE  (TOKENTYPE *);
size_t len_TOKENTYPE(const TOKENTYPE *);
int copy_TOKENTYPE(const TOKENTYPE *, TOKENTYPE *);


/*
ROBIN-TYPE ::= INTEGER
*/

typedef enum ROBIN_TYPE {
  RTYPE_GENERIC = 0,
  RTYPE_REGULAR = 1,
  RTYPE_DIRECTORY = 2,
  RTYPE_SYMLINK = 3,
  RTYPE_VOLUME = 4,
  RTYPE_GRAFT = 5,
  RTYPE_AUTHORITY = 6,
  RTYPE_VERSION = 7
} ROBIN_TYPE;

int enc_ROBIN_TYPE(unsigned char *, size_t, const ROBIN_TYPE *, size_t *);
int    dec_ROBIN_TYPE(const unsigned char *, size_t, ROBIN_TYPE *, size_t *);
void free_ROBIN_TYPE  (ROBIN_TYPE *);
size_t len_ROBIN_TYPE(const ROBIN_TYPE *);
int copy_ROBIN_TYPE(const ROBIN_TYPE *, ROBIN_TYPE *);


/*
ROBIN-ROUTETYPE ::= INTEGER
*/

typedef enum ROBIN_ROUTETYPE {
  RROUTE_DEAD = 0,
  RROUTE_PEER = 1,
  RROUTE_WREN = 2,
  RROUTE_IOWN = 3,
  RROUTE_FILTER = 4
} ROBIN_ROUTETYPE;

int enc_ROBIN_ROUTETYPE(unsigned char *, size_t, const ROBIN_ROUTETYPE *, size_t *);
int    dec_ROBIN_ROUTETYPE(const unsigned char *, size_t, ROBIN_ROUTETYPE *, size_t *);
void free_ROBIN_ROUTETYPE  (ROBIN_ROUTETYPE *);
size_t len_ROBIN_ROUTETYPE(const ROBIN_ROUTETYPE *);
int copy_ROBIN_ROUTETYPE(const ROBIN_ROUTETYPE *, ROBIN_ROUTETYPE *);


/*
ROBIN-RIGHT ::= BIT STRING {
  read(0),
  write(1),
  append(2),
  delete(3),
  lookup(4),
  insert(5),
  remove(6),
  rattr(7),
  wattr(8),
  execute(9),
  racl(10),
  wacl(11),
  admin(12),
  lock(13),
  notify(14),
  pfile(15),
  pdir(16),
  ponly(17),
  pstop(18),
  peruse(19),
  local1(24),
  local2(25),
  local3(26),
  local4(27),
  local5(28),
  local6(29),
  local7(30),
  local8(31)
}
*/

typedef struct ROBIN_RIGHT {
  uint32_t read:1;
  uint32_t write:1;
  uint32_t append:1;
  uint32_t delete:1;
  uint32_t lookup:1;
  uint32_t insert:1;
  uint32_t remove:1;
  uint32_t rattr:1;
  uint32_t wattr:1;
  uint32_t execute:1;
  uint32_t racl:1;
  uint32_t wacl:1;
  uint32_t admin:1;
  uint32_t lock:1;
  uint32_t notify:1;
  uint32_t pfile:1;
  uint32_t pdir:1;
  uint32_t ponly:1;
  uint32_t pstop:1;
  uint32_t peruse:1;
  uint32_t local1:1;
  uint32_t local2:1;
  uint32_t local3:1;
  uint32_t local4:1;
  uint32_t local5:1;
  uint32_t local6:1;
  uint32_t local7:1;
  uint32_t local8:1;
} ROBIN_RIGHT;


int enc_ROBIN_RIGHT(unsigned char *, size_t, const ROBIN_RIGHT *, size_t *);
int    dec_ROBIN_RIGHT(const unsigned char *, size_t, ROBIN_RIGHT *, size_t *);
void free_ROBIN_RIGHT  (ROBIN_RIGHT *);
size_t len_ROBIN_RIGHT(const ROBIN_RIGHT *);
int copy_ROBIN_RIGHT(const ROBIN_RIGHT *, ROBIN_RIGHT *);
unsigned ROBIN_RIGHT2int(ROBIN_RIGHT);
ROBIN_RIGHT int2ROBIN_RIGHT(unsigned);
const tbunits * asn1_ROBIN_RIGHT_units(void);

/*
ADDR-TYPE ::= INTEGER
*/

typedef enum ADDR_TYPE {
  ROBIN_ADDRESS_NONE = 0,
  ROBIN_ADDRESS_LOCAL = 1,
  ROBIN_ADDRESS_INET = 2,
  ROBIN_ADDRESS_INET6 = 24,
  ROBIN_ADDRESS_ADDRPORT = 256,
  ROBIN_ADDRESS_IPPORT = 257,
  ROBIN_ADDRESS_SELF = 258
} ADDR_TYPE;

int enc_ADDR_TYPE(unsigned char *, size_t, const ADDR_TYPE *, size_t *);
int    dec_ADDR_TYPE(const unsigned char *, size_t, ADDR_TYPE *, size_t *);
void free_ADDR_TYPE  (ADDR_TYPE *);
size_t len_ADDR_TYPE(const ADDR_TYPE *);
int copy_ADDR_TYPE(const ADDR_TYPE *, ADDR_TYPE *);


/*
ROBIN-UNSIGNED ::= UNSIGNED INTEGER
*/

typedef uint32_t ROBIN_UNSIGNED;

int enc_ROBIN_UNSIGNED(unsigned char *, size_t, const ROBIN_UNSIGNED *, size_t *);
int    dec_ROBIN_UNSIGNED(const unsigned char *, size_t, ROBIN_UNSIGNED *, size_t *);
void free_ROBIN_UNSIGNED  (ROBIN_UNSIGNED *);
size_t len_ROBIN_UNSIGNED(const ROBIN_UNSIGNED *);
int copy_ROBIN_UNSIGNED(const ROBIN_UNSIGNED *, ROBIN_UNSIGNED *);


/*
RobinData ::= OCTET STRING
*/

typedef tb_octet_string RobinData;

int enc_RobinData(unsigned char *, size_t, const RobinData *, size_t *);
int    dec_RobinData(const unsigned char *, size_t, RobinData *, size_t *);
void free_RobinData  (RobinData *);
size_t len_RobinData(const RobinData *);
int copy_RobinData(const RobinData *, RobinData *);


/*
RobinFilename ::= OCTET STRING
*/

typedef tb_octet_string RobinFilename;

int enc_RobinFilename(unsigned char *, size_t, const RobinFilename *, size_t *);
int    dec_RobinFilename(const unsigned char *, size_t, RobinFilename *, size_t *);
void free_RobinFilename  (RobinFilename *);
size_t len_RobinFilename(const RobinFilename *);
int copy_RobinFilename(const RobinFilename *, RobinFilename *);


/*
RobinFilenames ::= SEQUENCE OF RobinFilename
*/

typedef struct RobinFilenames {
  uint32_t len;
  RobinFilename *val;
} RobinFilenames;

int enc_RobinFilenames(unsigned char *, size_t, const RobinFilenames *, size_t *);
int    dec_RobinFilenames(const unsigned char *, size_t, RobinFilenames *, size_t *);
void free_RobinFilenames  (RobinFilenames *);
size_t len_RobinFilenames(const RobinFilenames *);
int copy_RobinFilenames(const RobinFilenames *, RobinFilenames *);
RobinFilename * add_RobinFilename(RobinFilenames *);
int del_RobinFilename(RobinFilenames *, RobinFilename *);


/*
RobinHostname ::= GeneralString
*/

typedef tb_general_string RobinHostname;

int enc_RobinHostname(unsigned char *, size_t, const RobinHostname *, size_t *);
int    dec_RobinHostname(const unsigned char *, size_t, RobinHostname *, size_t *);
void free_RobinHostname  (RobinHostname *);
size_t len_RobinHostname(const RobinHostname *);
int copy_RobinHostname(const RobinHostname *, RobinHostname *);


/*
RobinHostnames ::= SEQUENCE OF RobinHostname
*/

typedef struct RobinHostnames {
  uint32_t len;
  RobinHostname *val;
} RobinHostnames;

int enc_RobinHostnames(unsigned char *, size_t, const RobinHostnames *, size_t *);
int    dec_RobinHostnames(const unsigned char *, size_t, RobinHostnames *, size_t *);
void free_RobinHostnames  (RobinHostnames *);
size_t len_RobinHostnames(const RobinHostnames *);
int copy_RobinHostnames(const RobinHostnames *, RobinHostnames *);
RobinHostname * add_RobinHostname(RobinHostnames *);
int del_RobinHostname(RobinHostnames *, RobinHostname *);


/*
RobinHandle ::= SEQUENCE {
  vol[0]          ROBIN-UNSIGNED,
  ino[1]          ROBIN-UNSIGNED,
  gen[2]          ROBIN-UNSIGNED,
  ver[3]          ROBIN-UNSIGNED
}
*/

typedef struct RobinHandle {
  ROBIN_UNSIGNED vol;
  ROBIN_UNSIGNED ino;
  ROBIN_UNSIGNED gen;
  ROBIN_UNSIGNED ver;
} RobinHandle;

int enc_RobinHandle(unsigned char *, size_t, const RobinHandle *, size_t *);
int    dec_RobinHandle(const unsigned char *, size_t, RobinHandle *, size_t *);
void free_RobinHandle  (RobinHandle *);
size_t len_RobinHandle(const RobinHandle *);
int copy_RobinHandle(const RobinHandle *, RobinHandle *);


/*
RobinHandles ::= SEQUENCE OF RobinHandle
*/

typedef struct RobinHandles {
  uint32_t len;
  RobinHandle *val;
} RobinHandles;

int enc_RobinHandles(unsigned char *, size_t, const RobinHandles *, size_t *);
int    dec_RobinHandles(const unsigned char *, size_t, RobinHandles *, size_t *);
void free_RobinHandles  (RobinHandles *);
size_t len_RobinHandles(const RobinHandles *);
int copy_RobinHandles(const RobinHandles *, RobinHandles *);
RobinHandle * add_RobinHandle(RobinHandles *);
int del_RobinHandle(RobinHandles *, RobinHandle *);


/*
RobinRoute ::= SEQUENCE {
  hdl[0]          RobinHandle,
  prefix[1]       INTEGER
}
*/

typedef struct RobinRoute {
  RobinHandle hdl;
  int32_t prefix;
} RobinRoute;

int enc_RobinRoute(unsigned char *, size_t, const RobinRoute *, size_t *);
int    dec_RobinRoute(const unsigned char *, size_t, RobinRoute *, size_t *);
void free_RobinRoute  (RobinRoute *);
size_t len_RobinRoute(const RobinRoute *);
int copy_RobinRoute(const RobinRoute *, RobinRoute *);


/*
RobinRoutes ::= SEQUENCE OF RobinRoute
*/

typedef struct RobinRoutes {
  uint32_t len;
  RobinRoute *val;
} RobinRoutes;

int enc_RobinRoutes(unsigned char *, size_t, const RobinRoutes *, size_t *);
int    dec_RobinRoutes(const unsigned char *, size_t, RobinRoutes *, size_t *);
void free_RobinRoutes  (RobinRoutes *);
size_t len_RobinRoutes(const RobinRoutes *);
int copy_RobinRoutes(const RobinRoutes *, RobinRoutes *);
RobinRoute * add_RobinRoute(RobinRoutes *);
int del_RobinRoute(RobinRoutes *, RobinRoute *);


/*
ROBIN-WEEKDAY ::= INTEGER
*/

typedef enum ROBIN_WEEKDAY {
  ROBIN_WEEKDAY_MONDAY = 1,
  ROBIN_WEEKDAY_TUESDAY = 2,
  ROBIN_WEEKDAY_WEDNESDAY = 3,
  ROBIN_WEEKDAY_THURSDAY = 4,
  ROBIN_WEEKDAY_FRIDAY = 5,
  ROBIN_WEEKDAY_SATURDAY = 6,
  ROBIN_WEEKDAY_SUNDAY = 7
} ROBIN_WEEKDAY;

int enc_ROBIN_WEEKDAY(unsigned char *, size_t, const ROBIN_WEEKDAY *, size_t *);
int    dec_ROBIN_WEEKDAY(const unsigned char *, size_t, ROBIN_WEEKDAY *, size_t *);
void free_ROBIN_WEEKDAY  (ROBIN_WEEKDAY *);
size_t len_ROBIN_WEEKDAY(const ROBIN_WEEKDAY *);
int copy_ROBIN_WEEKDAY(const ROBIN_WEEKDAY *, ROBIN_WEEKDAY *);


/*
ROBIN-MONTH ::= INTEGER
*/

typedef enum ROBIN_MONTH {
  ROBIN_MONTH_JANUARY = 1,
  ROBIN_MONTH_FEBRUARY = 2,
  ROBIN_MONTH_MARCH = 3,
  ROBIN_MONTH_APRIL = 4,
  ROBIN_MONTH_MAY = 5,
  ROBIN_MONTH_JUNE = 6,
  ROBIN_MONTH_JULY = 7,
  ROBIN_MONTH_AUGUST = 8,
  ROBIN_MONTH_SEPTEMBER = 9,
  ROBIN_MONTH_OCTOBER = 10,
  ROBIN_MONTH_NOVEMBER = 11,
  ROBIN_MONTH_DECEMBER = 12
} ROBIN_MONTH;

int enc_ROBIN_MONTH(unsigned char *, size_t, const ROBIN_MONTH *, size_t *);
int    dec_ROBIN_MONTH(const unsigned char *, size_t, ROBIN_MONTH *, size_t *);
void free_ROBIN_MONTH  (ROBIN_MONTH *);
size_t len_ROBIN_MONTH(const ROBIN_MONTH *);
int copy_ROBIN_MONTH(const ROBIN_MONTH *, ROBIN_MONTH *);


/*
RobinDateSpec ::= SEQUENCE {
  year[0]         INTEGER OPTIONAL,
  month[1]        ROBIN-MONTH OPTIONAL,
  weekday[2]      ROBIN-WEEKDAY OPTIONAL,
  day[3]          INTEGER OPTIONAL,
  hour[4]         INTEGER OPTIONAL,
  minute[5]       INTEGER OPTIONAL,
  second[6]       INTEGER OPTIONAL,
  nanosec[7]      INTEGER OPTIONAL
}
*/

typedef struct RobinDateSpec {
  int32_t *year;
  ROBIN_MONTH *month;
  ROBIN_WEEKDAY *weekday;
  int32_t *day;
  int32_t *hour;
  int32_t *minute;
  int32_t *second;
  int32_t *nanosec;
} RobinDateSpec;

int enc_RobinDateSpec(unsigned char *, size_t, const RobinDateSpec *, size_t *);
int    dec_RobinDateSpec(const unsigned char *, size_t, RobinDateSpec *, size_t *);
void free_RobinDateSpec  (RobinDateSpec *);
size_t len_RobinDateSpec(const RobinDateSpec *);
int copy_RobinDateSpec(const RobinDateSpec *, RobinDateSpec *);


/*
RobinTime ::= SEQUENCE {
  secs[0]         INTEGER64,
  nsec[1]         INTEGER
}
*/

typedef struct RobinTime {
  int64_t secs;
  int32_t nsec;
} RobinTime;

int enc_RobinTime(unsigned char *, size_t, const RobinTime *, size_t *);
int    dec_RobinTime(const unsigned char *, size_t, RobinTime *, size_t *);
void free_RobinTime  (RobinTime *);
size_t len_RobinTime(const RobinTime *);
int copy_RobinTime(const RobinTime *, RobinTime *);


/*
RobinTimes ::= SEQUENCE OF RobinTime
*/

typedef struct RobinTimes {
  uint32_t len;
  RobinTime *val;
} RobinTimes;

int enc_RobinTimes(unsigned char *, size_t, const RobinTimes *, size_t *);
int    dec_RobinTimes(const unsigned char *, size_t, RobinTimes *, size_t *);
void free_RobinTimes  (RobinTimes *);
size_t len_RobinTimes(const RobinTimes *);
int copy_RobinTimes(const RobinTimes *, RobinTimes *);
RobinTime * add_RobinTime(RobinTimes *);
int del_RobinTime(RobinTimes *, RobinTime *);


/*
RobinTimeDelta ::= SEQUENCE {
  start[0]        RobinTime,
  stop[1]         RobinTime
}
*/

typedef struct RobinTimeDelta {
  RobinTime start;
  RobinTime stop;
} RobinTimeDelta;

int enc_RobinTimeDelta(unsigned char *, size_t, const RobinTimeDelta *, size_t *);
int    dec_RobinTimeDelta(const unsigned char *, size_t, RobinTimeDelta *, size_t *);
void free_RobinTimeDelta  (RobinTimeDelta *);
size_t len_RobinTimeDelta(const RobinTimeDelta *);
int copy_RobinTimeDelta(const RobinTimeDelta *, RobinTimeDelta *);


/*
RobinHostAddress ::= SEQUENCE {
  addr-type[0]    ADDR-TYPE,
  port[1]         INTEGER,
  address[2]      OCTET STRING
}
*/

typedef struct RobinHostAddress {
  ADDR_TYPE addr_type;
  int32_t port;
  tb_octet_string address;
} RobinHostAddress;

int enc_RobinHostAddress(unsigned char *, size_t, const RobinHostAddress *, size_t *);
int    dec_RobinHostAddress(const unsigned char *, size_t, RobinHostAddress *, size_t *);
void free_RobinHostAddress  (RobinHostAddress *);
size_t len_RobinHostAddress(const RobinHostAddress *);
int copy_RobinHostAddress(const RobinHostAddress *, RobinHostAddress *);


/*
RobinHostAddresses ::= SEQUENCE OF RobinHostAddress
*/

typedef struct RobinHostAddresses {
  uint32_t len;
  RobinHostAddress *val;
} RobinHostAddresses;

int enc_RobinHostAddresses(unsigned char *, size_t, const RobinHostAddresses *, size_t *);
int    dec_RobinHostAddresses(const unsigned char *, size_t, RobinHostAddresses *, size_t *);
void free_RobinHostAddresses  (RobinHostAddresses *);
size_t len_RobinHostAddresses(const RobinHostAddresses *);
int copy_RobinHostAddresses(const RobinHostAddresses *, RobinHostAddresses *);
RobinHostAddress * add_RobinHostAddress(RobinHostAddresses *);
int del_RobinHostAddress(RobinHostAddresses *, RobinHostAddress *);


/*
RobinHost ::= SEQUENCE {
  hostname[0]     RobinHostname,
  addresses[1]    RobinHostAddresses
}
*/

typedef struct RobinHost {
  RobinHostname hostname;
  RobinHostAddresses addresses;
} RobinHost;

int enc_RobinHost(unsigned char *, size_t, const RobinHost *, size_t *);
int    dec_RobinHost(const unsigned char *, size_t, RobinHost *, size_t *);
void free_RobinHost  (RobinHost *);
size_t len_RobinHost(const RobinHost *);
int copy_RobinHost(const RobinHost *, RobinHost *);


/*
RobinHosts ::= SEQUENCE OF RobinHost
*/

typedef struct RobinHosts {
  uint32_t len;
  RobinHost *val;
} RobinHosts;

int enc_RobinHosts(unsigned char *, size_t, const RobinHosts *, size_t *);
int    dec_RobinHosts(const unsigned char *, size_t, RobinHosts *, size_t *);
void free_RobinHosts  (RobinHosts *);
size_t len_RobinHosts(const RobinHosts *);
int copy_RobinHosts(const RobinHosts *, RobinHosts *);
RobinHost * add_RobinHost(RobinHosts *);
int del_RobinHost(RobinHosts *, RobinHost *);


/*
RobinCell ::= SEQUENCE {
  cellname[0]     RobinHostname,
  hosts[1]        RobinHosts,
  wrens[2]        RobinHosts
}
*/

typedef struct RobinCell {
  RobinHostname cellname;
  RobinHosts hosts;
  RobinHosts wrens;
} RobinCell;

int enc_RobinCell(unsigned char *, size_t, const RobinCell *, size_t *);
int    dec_RobinCell(const unsigned char *, size_t, RobinCell *, size_t *);
void free_RobinCell  (RobinCell *);
size_t len_RobinCell(const RobinCell *);
int copy_RobinCell(const RobinCell *, RobinCell *);


/*
RobinCells ::= SEQUENCE OF RobinCell
*/

typedef struct RobinCells {
  uint32_t len;
  RobinCell *val;
} RobinCells;

int enc_RobinCells(unsigned char *, size_t, const RobinCells *, size_t *);
int    dec_RobinCells(const unsigned char *, size_t, RobinCells *, size_t *);
void free_RobinCells  (RobinCells *);
size_t len_RobinCells(const RobinCells *);
int copy_RobinCells(const RobinCells *, RobinCells *);
RobinCell * add_RobinCell(RobinCells *);
int del_RobinCell(RobinCells *, RobinCell *);


/*
RobinPrincipal ::= SEQUENCE {
  name[0]         GeneralString,
  cell[1]         GeneralString
}
*/

typedef struct RobinPrincipal {
  tb_general_string name;
  tb_general_string cell;
} RobinPrincipal;

int enc_RobinPrincipal(unsigned char *, size_t, const RobinPrincipal *, size_t *);
int    dec_RobinPrincipal(const unsigned char *, size_t, RobinPrincipal *, size_t *);
void free_RobinPrincipal  (RobinPrincipal *);
size_t len_RobinPrincipal(const RobinPrincipal *);
int copy_RobinPrincipal(const RobinPrincipal *, RobinPrincipal *);


/*
RobinPrincipals ::= SEQUENCE OF RobinPrincipal
*/

typedef struct RobinPrincipals {
  uint32_t len;
  RobinPrincipal *val;
} RobinPrincipals;

int enc_RobinPrincipals(unsigned char *, size_t, const RobinPrincipals *, size_t *);
int    dec_RobinPrincipals(const unsigned char *, size_t, RobinPrincipals *, size_t *);
void free_RobinPrincipals  (RobinPrincipals *);
size_t len_RobinPrincipals(const RobinPrincipals *);
int copy_RobinPrincipals(const RobinPrincipals *, RobinPrincipals *);
RobinPrincipal * add_RobinPrincipal(RobinPrincipals *);
int del_RobinPrincipal(RobinPrincipals *, RobinPrincipal *);


/*
RobinPartition ::= OCTET STRING
*/

typedef tb_octet_string RobinPartition;

int enc_RobinPartition(unsigned char *, size_t, const RobinPartition *, size_t *);
int    dec_RobinPartition(const unsigned char *, size_t, RobinPartition *, size_t *);
void free_RobinPartition  (RobinPartition *);
size_t len_RobinPartition(const RobinPartition *);
int copy_RobinPartition(const RobinPartition *, RobinPartition *);


/*
RobinPartitions ::= SEQUENCE OF RobinPartition
*/

typedef struct RobinPartitions {
  uint32_t len;
  RobinPartition *val;
} RobinPartitions;

int enc_RobinPartitions(unsigned char *, size_t, const RobinPartitions *, size_t *);
int    dec_RobinPartitions(const unsigned char *, size_t, RobinPartitions *, size_t *);
void free_RobinPartitions  (RobinPartitions *);
size_t len_RobinPartitions(const RobinPartitions *);
int copy_RobinPartitions(const RobinPartitions *, RobinPartitions *);
RobinPartition * add_RobinPartition(RobinPartitions *);
int del_RobinPartition(RobinPartitions *, RobinPartition *);


/*
RobinDisk ::= SEQUENCE {
  hostname[0]     RobinHostname,
  pid[1]          RobinPartition
}
*/

typedef struct RobinDisk {
  RobinHostname hostname;
  RobinPartition pid;
} RobinDisk;

int enc_RobinDisk(unsigned char *, size_t, const RobinDisk *, size_t *);
int    dec_RobinDisk(const unsigned char *, size_t, RobinDisk *, size_t *);
void free_RobinDisk  (RobinDisk *);
size_t len_RobinDisk(const RobinDisk *);
int copy_RobinDisk(const RobinDisk *, RobinDisk *);


/*
RobinDisks ::= SEQUENCE OF RobinDisk
*/

typedef struct RobinDisks {
  uint32_t len;
  RobinDisk *val;
} RobinDisks;

int enc_RobinDisks(unsigned char *, size_t, const RobinDisks *, size_t *);
int    dec_RobinDisks(const unsigned char *, size_t, RobinDisks *, size_t *);
void free_RobinDisks  (RobinDisks *);
size_t len_RobinDisks(const RobinDisks *);
int copy_RobinDisks(const RobinDisks *, RobinDisks *);
RobinDisk * add_RobinDisk(RobinDisks *);
int del_RobinDisk(RobinDisks *, RobinDisk *);


/*
RobinDiskFlags ::= BIT STRING {
  available(0),
  up(1),
  down(2),
  drain(3),
  readonly(4),
  fickle(5),
  compact(6),
  verify(7),
  repair(8),
  failure(9),
  powersave(10),
  local1(24),
  local2(25),
  local3(26),
  local4(27),
  local5(28),
  local6(29),
  local7(30),
  local8(31)
}
*/

typedef struct RobinDiskFlags {
  uint32_t available:1;
  uint32_t up:1;
  uint32_t down:1;
  uint32_t drain:1;
  uint32_t readonly:1;
  uint32_t fickle:1;
  uint32_t compact:1;
  uint32_t verify:1;
  uint32_t repair:1;
  uint32_t failure:1;
  uint32_t powersave:1;
  uint32_t local1:1;
  uint32_t local2:1;
  uint32_t local3:1;
  uint32_t local4:1;
  uint32_t local5:1;
  uint32_t local6:1;
  uint32_t local7:1;
  uint32_t local8:1;
} RobinDiskFlags;


int enc_RobinDiskFlags(unsigned char *, size_t, const RobinDiskFlags *, size_t *);
int    dec_RobinDiskFlags(const unsigned char *, size_t, RobinDiskFlags *, size_t *);
void free_RobinDiskFlags  (RobinDiskFlags *);
size_t len_RobinDiskFlags(const RobinDiskFlags *);
int copy_RobinDiskFlags(const RobinDiskFlags *, RobinDiskFlags *);
unsigned RobinDiskFlags2int(RobinDiskFlags);
RobinDiskFlags int2RobinDiskFlags(unsigned);
const tbunits * asn1_RobinDiskFlags_units(void);

/*
RobinDiskTarget ::= SEQUENCE {
  size[0]         INTEGER64 OPTIONAL,
  percent[1]      INTEGER OPTIONAL
}
*/

typedef struct RobinDiskTarget {
  int64_t *size;
  int32_t *percent;
} RobinDiskTarget;

int enc_RobinDiskTarget(unsigned char *, size_t, const RobinDiskTarget *, size_t *);
int    dec_RobinDiskTarget(const unsigned char *, size_t, RobinDiskTarget *, size_t *);
void free_RobinDiskTarget  (RobinDiskTarget *);
size_t len_RobinDiskTarget(const RobinDiskTarget *);
int copy_RobinDiskTarget(const RobinDiskTarget *, RobinDiskTarget *);


/*
RobinDiskStats ::= SEQUENCE {
  operations[0]   INTEGER64,
  rbandwidth[1]   INTEGER64,
  wbandwidth[2]   INTEGER64
}
*/

typedef struct RobinDiskStats {
  int64_t operations;
  int64_t rbandwidth;
  int64_t wbandwidth;
} RobinDiskStats;

int enc_RobinDiskStats(unsigned char *, size_t, const RobinDiskStats *, size_t *);
int    dec_RobinDiskStats(const unsigned char *, size_t, RobinDiskStats *, size_t *);
void free_RobinDiskStats  (RobinDiskStats *);
size_t len_RobinDiskStats(const RobinDiskStats *);
int copy_RobinDiskStats(const RobinDiskStats *, RobinDiskStats *);


/*
RobinRights ::= SEQUENCE {
  rights[0]       ROBIN-RIGHT,
  principal[1]    RobinPrincipal
}
*/

typedef struct RobinRights {
  ROBIN_RIGHT rights;
  RobinPrincipal principal;
} RobinRights;

int enc_RobinRights(unsigned char *, size_t, const RobinRights *, size_t *);
int    dec_RobinRights(const unsigned char *, size_t, RobinRights *, size_t *);
void free_RobinRights  (RobinRights *);
size_t len_RobinRights(const RobinRights *);
int copy_RobinRights(const RobinRights *, RobinRights *);


/*
RobinRightsList ::= SEQUENCE OF RobinRights
*/

typedef struct RobinRightsList {
  uint32_t len;
  RobinRights *val;
} RobinRightsList;

int enc_RobinRightsList(unsigned char *, size_t, const RobinRightsList *, size_t *);
int    dec_RobinRightsList(const unsigned char *, size_t, RobinRightsList *, size_t *);
void free_RobinRightsList  (RobinRightsList *);
size_t len_RobinRightsList(const RobinRightsList *);
int copy_RobinRightsList(const RobinRightsList *, RobinRightsList *);
RobinRights * add_RobinRights(RobinRightsList *);
int del_RobinRights(RobinRightsList *, RobinRights *);


/*
RobinAcl ::= SEQUENCE {
  rights[0]       ROBIN-RIGHT,
  nrights[1]      ROBIN-RIGHT,
  arights[2]      ROBIN-RIGHT,
  owner[3]        RobinPrincipal,
  list[4]         RobinRightsList OPTIONAL
}
*/

typedef struct RobinAcl {
  ROBIN_RIGHT rights;
  ROBIN_RIGHT nrights;
  ROBIN_RIGHT arights;
  RobinPrincipal owner;
  RobinRightsList *list;
} RobinAcl;

int enc_RobinAcl(unsigned char *, size_t, const RobinAcl *, size_t *);
int    dec_RobinAcl(const unsigned char *, size_t, RobinAcl *, size_t *);
void free_RobinAcl  (RobinAcl *);
size_t len_RobinAcl(const RobinAcl *);
int copy_RobinAcl(const RobinAcl *, RobinAcl *);


/*
RobinParent ::= SEQUENCE {
  phdl[0]         RobinHandle,
  name[1]         RobinFilename
}
*/

typedef struct RobinParent {
  RobinHandle phdl;
  RobinFilename name;
} RobinParent;

int enc_RobinParent(unsigned char *, size_t, const RobinParent *, size_t *);
int    dec_RobinParent(const unsigned char *, size_t, RobinParent *, size_t *);
void free_RobinParent  (RobinParent *);
size_t len_RobinParent(const RobinParent *);
int copy_RobinParent(const RobinParent *, RobinParent *);


/*
RobinFamily ::= SEQUENCE OF RobinParent
*/

typedef struct RobinFamily {
  uint32_t len;
  RobinParent *val;
} RobinFamily;

int enc_RobinFamily(unsigned char *, size_t, const RobinFamily *, size_t *);
int    dec_RobinFamily(const unsigned char *, size_t, RobinFamily *, size_t *);
void free_RobinFamily  (RobinFamily *);
size_t len_RobinFamily(const RobinFamily *);
int copy_RobinFamily(const RobinFamily *, RobinFamily *);
RobinParent * add_RobinParent(RobinFamily *);
int del_RobinParent(RobinFamily *, RobinParent *);


/*
RobinAttributes ::= SEQUENCE {
  type[0]         ROBIN-TYPE OPTIONAL,
  acl[1]          RobinAcl OPTIONAL,
  mtime[2]        RobinTime OPTIONAL,
  atime[3]        RobinTime OPTIONAL,
  ctime[4]        RobinTime OPTIONAL,
  size[5]         INTEGER64 OPTIONAL,
  family[6]       RobinFamily OPTIONAL
}
*/

typedef struct RobinAttributes {
  ROBIN_TYPE *type;
  RobinAcl *acl;
  RobinTime *mtime;
  RobinTime *atime;
  RobinTime *ctime;
  int64_t *size;
  RobinFamily *family;
} RobinAttributes;

int enc_RobinAttributes(unsigned char *, size_t, const RobinAttributes *, size_t *);
int    dec_RobinAttributes(const unsigned char *, size_t, RobinAttributes *, size_t *);
void free_RobinAttributes  (RobinAttributes *);
size_t len_RobinAttributes(const RobinAttributes *);
int copy_RobinAttributes(const RobinAttributes *, RobinAttributes *);


/*
RobinDirentry ::= SEQUENCE {
  hdl[0]          RobinHandle,
  type[1]         ROBIN-TYPE,
  name[2]         RobinFilename
}
*/

typedef struct RobinDirentry {
  RobinHandle hdl;
  ROBIN_TYPE type;
  RobinFilename name;
} RobinDirentry;

int enc_RobinDirentry(unsigned char *, size_t, const RobinDirentry *, size_t *);
int    dec_RobinDirentry(const unsigned char *, size_t, RobinDirentry *, size_t *);
void free_RobinDirentry  (RobinDirentry *);
size_t len_RobinDirentry(const RobinDirentry *);
int copy_RobinDirentry(const RobinDirentry *, RobinDirentry *);


/*
RobinDirentries ::= SEQUENCE OF RobinDirentry
*/

typedef struct RobinDirentries {
  uint32_t len;
  RobinDirentry *val;
} RobinDirentries;

int enc_RobinDirentries(unsigned char *, size_t, const RobinDirentries *, size_t *);
int    dec_RobinDirentries(const unsigned char *, size_t, RobinDirentries *, size_t *);
void free_RobinDirentries  (RobinDirentries *);
size_t len_RobinDirentries(const RobinDirentries *);
int copy_RobinDirentries(const RobinDirentries *, RobinDirentries *);
RobinDirentry * add_RobinDirentry(RobinDirentries *);
int del_RobinDirentry(RobinDirentries *, RobinDirentry *);


/*
RobinChecksum ::= SEQUENCE {
  cksumtype[0]    ROBIN-CKSUMTYPE,
  checksum[1]     OCTET STRING
}
*/

typedef struct RobinChecksum {
  ROBIN_CKSUMTYPE cksumtype;
  tb_octet_string checksum;
} RobinChecksum;

int enc_RobinChecksum(unsigned char *, size_t, const RobinChecksum *, size_t *);
int    dec_RobinChecksum(const unsigned char *, size_t, RobinChecksum *, size_t *);
void free_RobinChecksum  (RobinChecksum *);
size_t len_RobinChecksum(const RobinChecksum *);
int copy_RobinChecksum(const RobinChecksum *, RobinChecksum *);


/*
RobinChecksums ::= SEQUENCE OF RobinChecksum
*/

typedef struct RobinChecksums {
  uint32_t len;
  RobinChecksum *val;
} RobinChecksums;

int enc_RobinChecksums(unsigned char *, size_t, const RobinChecksums *, size_t *);
int    dec_RobinChecksums(const unsigned char *, size_t, RobinChecksums *, size_t *);
void free_RobinChecksums  (RobinChecksums *);
size_t len_RobinChecksums(const RobinChecksums *);
int copy_RobinChecksums(const RobinChecksums *, RobinChecksums *);
RobinChecksum * add_RobinChecksum(RobinChecksums *);
int del_RobinChecksum(RobinChecksums *, RobinChecksum *);


/*
RobinSignature ::= SEQUENCE {
  sigtype[0]      TOKENTYPE,
  keytype[1]      INTEGER,
  kvno[1]         INTEGER,
  sigdata[2]      OCTET STRING
}
*/

typedef struct RobinSignature {
  TOKENTYPE sigtype;
  int32_t keytype;
  int32_t kvno;
  tb_octet_string sigdata;
} RobinSignature;

int enc_RobinSignature(unsigned char *, size_t, const RobinSignature *, size_t *);
int    dec_RobinSignature(const unsigned char *, size_t, RobinSignature *, size_t *);
void free_RobinSignature  (RobinSignature *);
size_t len_RobinSignature(const RobinSignature *);
int copy_RobinSignature(const RobinSignature *, RobinSignature *);


/*
RobinSignatures ::= SEQUENCE OF RobinSignature
*/

typedef struct RobinSignatures {
  uint32_t len;
  RobinSignature *val;
} RobinSignatures;

int enc_RobinSignatures(unsigned char *, size_t, const RobinSignatures *, size_t *);
int    dec_RobinSignatures(const unsigned char *, size_t, RobinSignatures *, size_t *);
void free_RobinSignatures  (RobinSignatures *);
size_t len_RobinSignatures(const RobinSignatures *);
int copy_RobinSignatures(const RobinSignatures *, RobinSignatures *);
RobinSignature * add_RobinSignature(RobinSignatures *);
int del_RobinSignature(RobinSignatures *, RobinSignature *);


/*
RobinEncryptionKey ::= SEQUENCE {
  keytype[0]      INTEGER,
  keyvalue[1]     OCTET STRING
}
*/

typedef struct RobinEncryptionKey {
  int32_t keytype;
  tb_octet_string keyvalue;
} RobinEncryptionKey;

int enc_RobinEncryptionKey(unsigned char *, size_t, const RobinEncryptionKey *, size_t *);
int    dec_RobinEncryptionKey(const unsigned char *, size_t, RobinEncryptionKey *, size_t *);
void free_RobinEncryptionKey  (RobinEncryptionKey *);
size_t len_RobinEncryptionKey(const RobinEncryptionKey *);
int copy_RobinEncryptionKey(const RobinEncryptionKey *, RobinEncryptionKey *);


/*
RobinEncryptionKeys ::= SEQUENCE OF RobinEncryptionKey
*/

typedef struct RobinEncryptionKeys {
  uint32_t len;
  RobinEncryptionKey *val;
} RobinEncryptionKeys;

int enc_RobinEncryptionKeys(unsigned char *, size_t, const RobinEncryptionKeys *, size_t *);
int    dec_RobinEncryptionKeys(const unsigned char *, size_t, RobinEncryptionKeys *, size_t *);
void free_RobinEncryptionKeys  (RobinEncryptionKeys *);
size_t len_RobinEncryptionKeys(const RobinEncryptionKeys *);
int copy_RobinEncryptionKeys(const RobinEncryptionKeys *, RobinEncryptionKeys *);
RobinEncryptionKey * add_RobinEncryptionKey(RobinEncryptionKeys *);
int del_RobinEncryptionKey(RobinEncryptionKeys *, RobinEncryptionKey *);


/*
RobinTokenData ::= SEQUENCE {
  hdl[0]          RobinHandle,
  prefix[1]       INTEGER,
  issued[2]       RobinTime,
  expire[3]       RobinTime OPTIONAL,
  signator[4]     RobinPrincipal,
  principal[5]    RobinPrincipal,
  right[6]        ROBIN-RIGHT,
  private[7]      OCTET STRING OPTIONAL,
  partition[8]    RobinPartition OPTIONAL
}
*/

typedef struct RobinTokenData {
  RobinHandle hdl;
  int32_t prefix;
  RobinTime issued;
  RobinTime *expire;
  RobinPrincipal signator;
  RobinPrincipal principal;
  ROBIN_RIGHT right;
  tb_octet_string *private;
  RobinPartition *partition;
} RobinTokenData;

int enc_RobinTokenData(unsigned char *, size_t, const RobinTokenData *, size_t *);
int    dec_RobinTokenData(const unsigned char *, size_t, RobinTokenData *, size_t *);
void free_RobinTokenData  (RobinTokenData *);
size_t len_RobinTokenData(const RobinTokenData *);
int copy_RobinTokenData(const RobinTokenData *, RobinTokenData *);


/*
RobinToken ::= SEQUENCE {
  data[0]         RobinTokenData,
  sigs[1]         RobinSignatures
}
*/

typedef struct RobinToken {
  RobinTokenData data;
  RobinSignatures sigs;
} RobinToken;

int enc_RobinToken(unsigned char *, size_t, const RobinToken *, size_t *);
int    dec_RobinToken(const unsigned char *, size_t, RobinToken *, size_t *);
void free_RobinToken  (RobinToken *);
size_t len_RobinToken(const RobinToken *);
int copy_RobinToken(const RobinToken *, RobinToken *);


/*
RobinTokens ::= SEQUENCE OF RobinToken
*/

typedef struct RobinTokens {
  uint32_t len;
  RobinToken *val;
} RobinTokens;

int enc_RobinTokens(unsigned char *, size_t, const RobinTokens *, size_t *);
int    dec_RobinTokens(const unsigned char *, size_t, RobinTokens *, size_t *);
void free_RobinTokens  (RobinTokens *);
size_t len_RobinTokens(const RobinTokens *);
int copy_RobinTokens(const RobinTokens *, RobinTokens *);
RobinToken * add_RobinToken(RobinTokens *);
int del_RobinToken(RobinTokens *, RobinToken *);


/*
RobinLock ::= SEQUENCE {
  type[0]         ROBIN-LOCKTYPE,
  expiry[1]       RobinTime OPTIONAL,
  lower[2]        INTEGER64 OPTIONAL,
  upper[3]        INTEGER64 OPTIONAL
}
*/

typedef struct RobinLock {
  ROBIN_LOCKTYPE type;
  RobinTime *expiry;
  int64_t *lower;
  int64_t *upper;
} RobinLock;

int enc_RobinLock(unsigned char *, size_t, const RobinLock *, size_t *);
int    dec_RobinLock(const unsigned char *, size_t, RobinLock *, size_t *);
void free_RobinLock  (RobinLock *);
size_t len_RobinLock(const RobinLock *);
int copy_RobinLock(const RobinLock *, RobinLock *);


/*
RobinLocks ::= SEQUENCE OF RobinLock
*/

typedef struct RobinLocks {
  uint32_t len;
  RobinLock *val;
} RobinLocks;

int enc_RobinLocks(unsigned char *, size_t, const RobinLocks *, size_t *);
int    dec_RobinLocks(const unsigned char *, size_t, RobinLocks *, size_t *);
void free_RobinLocks  (RobinLocks *);
size_t len_RobinLocks(const RobinLocks *);
int copy_RobinLocks(const RobinLocks *, RobinLocks *);
RobinLock * add_RobinLock(RobinLocks *);
int del_RobinLock(RobinLocks *, RobinLock *);


/*
RobinRouterFlags ::= BIT STRING {
  inprogress(1),
  placeholder(2),
  valid(3),
  deleted(4),
  readonly(5),
  fickle(6),
  master(7),
  wipeme(8),
  offline(9),
  harderror(10),
  softerror(11)
}
*/

typedef struct RobinRouterFlags {
  uint32_t inprogress:1;
  uint32_t placeholder:1;
  uint32_t valid:1;
  uint32_t deleted:1;
  uint32_t readonly:1;
  uint32_t fickle:1;
  uint32_t master:1;
  uint32_t wipeme:1;
  uint32_t offline:1;
  uint32_t harderror:1;
  uint32_t softerror:1;
} RobinRouterFlags;


int enc_RobinRouterFlags(unsigned char *, size_t, const RobinRouterFlags *, size_t *);
int    dec_RobinRouterFlags(const unsigned char *, size_t, RobinRouterFlags *, size_t *);
void free_RobinRouterFlags  (RobinRouterFlags *);
size_t len_RobinRouterFlags(const RobinRouterFlags *);
int copy_RobinRouterFlags(const RobinRouterFlags *, RobinRouterFlags *);
unsigned RobinRouterFlags2int(RobinRouterFlags);
RobinRouterFlags int2RobinRouterFlags(unsigned);
const tbunits * asn1_RobinRouterFlags_units(void);

/*
RobinQuota ::= SEQUENCE {
  space[0]        INTEGER64,
  nodes[1]        INTEGER64
}
*/

typedef struct RobinQuota {
  int64_t space;
  int64_t nodes;
} RobinQuota;

int enc_RobinQuota(unsigned char *, size_t, const RobinQuota *, size_t *);
int    dec_RobinQuota(const unsigned char *, size_t, RobinQuota *, size_t *);
void free_RobinQuota  (RobinQuota *);
size_t len_RobinQuota(const RobinQuota *);
int copy_RobinQuota(const RobinQuota *, RobinQuota *);


/*
RobinProtectTime ::= SEQUENCE {
  start[0]        RobinDateSpec,
  stop[1]         RobinDateSpec
}
*/

typedef struct RobinProtectTime {
  RobinDateSpec start;
  RobinDateSpec stop;
} RobinProtectTime;

int enc_RobinProtectTime(unsigned char *, size_t, const RobinProtectTime *, size_t *);
int    dec_RobinProtectTime(const unsigned char *, size_t, RobinProtectTime *, size_t *);
void free_RobinProtectTime  (RobinProtectTime *);
size_t len_RobinProtectTime(const RobinProtectTime *);
int copy_RobinProtectTime(const RobinProtectTime *, RobinProtectTime *);


/*
RobinProtectTimes ::= SEQUENCE OF RobinProtectTime
*/

typedef struct RobinProtectTimes {
  uint32_t len;
  RobinProtectTime *val;
} RobinProtectTimes;

int enc_RobinProtectTimes(unsigned char *, size_t, const RobinProtectTimes *, size_t *);
int    dec_RobinProtectTimes(const unsigned char *, size_t, RobinProtectTimes *, size_t *);
void free_RobinProtectTimes  (RobinProtectTimes *);
size_t len_RobinProtectTimes(const RobinProtectTimes *);
int copy_RobinProtectTimes(const RobinProtectTimes *, RobinProtectTimes *);
RobinProtectTime * add_RobinProtectTime(RobinProtectTimes *);
int del_RobinProtectTime(RobinProtectTimes *, RobinProtectTime *);


/*
RobinProtectInfo ::= SEQUENCE {
  need[0]         INTEGER OPTIONAL,
  want[1]         INTEGER OPTIONAL,
  limit[2]        INTEGER OPTIONAL,
  time[3]         RobinProtectTimes
}
*/

typedef struct RobinProtectInfo {
  int32_t *need;
  int32_t *want;
  int32_t *limit;
  RobinProtectTimes time;
} RobinProtectInfo;

int enc_RobinProtectInfo(unsigned char *, size_t, const RobinProtectInfo *, size_t *);
int    dec_RobinProtectInfo(const unsigned char *, size_t, RobinProtectInfo *, size_t *);
void free_RobinProtectInfo  (RobinProtectInfo *);
size_t len_RobinProtectInfo(const RobinProtectInfo *);
int copy_RobinProtectInfo(const RobinProtectInfo *, RobinProtectInfo *);


/*
RobinProtectRule ::= SEQUENCE {
  host[0]         RobinHostname,
  total[1]        RobinProtectInfo,
  local[2]        RobinProtectInfo,
  remote[3]       RobinProtectInfo
}
*/

typedef struct RobinProtectRule {
  RobinHostname host;
  RobinProtectInfo total;
  RobinProtectInfo local;
  RobinProtectInfo remote;
} RobinProtectRule;

int enc_RobinProtectRule(unsigned char *, size_t, const RobinProtectRule *, size_t *);
int    dec_RobinProtectRule(const unsigned char *, size_t, RobinProtectRule *, size_t *);
void free_RobinProtectRule  (RobinProtectRule *);
size_t len_RobinProtectRule(const RobinProtectRule *);
int copy_RobinProtectRule(const RobinProtectRule *, RobinProtectRule *);


/*
RobinProtectRules ::= SEQUENCE OF RobinProtectRule
*/

typedef struct RobinProtectRules {
  uint32_t len;
  RobinProtectRule *val;
} RobinProtectRules;

int enc_RobinProtectRules(unsigned char *, size_t, const RobinProtectRules *, size_t *);
int    dec_RobinProtectRules(const unsigned char *, size_t, RobinProtectRules *, size_t *);
void free_RobinProtectRules  (RobinProtectRules *);
size_t len_RobinProtectRules(const RobinProtectRules *);
int copy_RobinProtectRules(const RobinProtectRules *, RobinProtectRules *);
RobinProtectRule * add_RobinProtectRule(RobinProtectRules *);
int del_RobinProtectRule(RobinProtectRules *, RobinProtectRule *);


/*
RobinProtect ::= SEQUENCE {
  total[0]        RobinProtectInfo,
  local[1]        RobinProtectInfo,
  remote[2]       RobinProtectInfo,
  rules[3]        RobinProtectRules
}
*/

typedef struct RobinProtect {
  RobinProtectInfo total;
  RobinProtectInfo local;
  RobinProtectInfo remote;
  RobinProtectRules rules;
} RobinProtect;

int enc_RobinProtect(unsigned char *, size_t, const RobinProtect *, size_t *);
int    dec_RobinProtect(const unsigned char *, size_t, RobinProtect *, size_t *);
void free_RobinProtect  (RobinProtect *);
size_t len_RobinProtect(const RobinProtect *);
int copy_RobinProtect(const RobinProtect *, RobinProtect *);


/*
RobinProtectSource ::= SEQUENCE {
  vhdl[0]         RobinHandle OPTIONAL,
  disk[1]         RobinDisk OPTIONAL
}
*/

typedef struct RobinProtectSource {
  RobinHandle *vhdl;
  RobinDisk *disk;
} RobinProtectSource;

int enc_RobinProtectSource(unsigned char *, size_t, const RobinProtectSource *, size_t *);
int    dec_RobinProtectSource(const unsigned char *, size_t, RobinProtectSource *, size_t *);
void free_RobinProtectSource  (RobinProtectSource *);
size_t len_RobinProtectSource(const RobinProtectSource *);
int copy_RobinProtectSource(const RobinProtectSource *, RobinProtectSource *);


/*
RobinProtectNode ::= SEQUENCE {
  source[0]       RobinProtectSource,
  route[1]        RobinRoute,
  type[2]         ROBIN-TYPE OPTIONAL,
  protect[3]      RobinProtect
}
*/

typedef struct RobinProtectNode {
  RobinProtectSource source;
  RobinRoute route;
  ROBIN_TYPE *type;
  RobinProtect protect;
} RobinProtectNode;

int enc_RobinProtectNode(unsigned char *, size_t, const RobinProtectNode *, size_t *);
int    dec_RobinProtectNode(const unsigned char *, size_t, RobinProtectNode *, size_t *);
void free_RobinProtectNode  (RobinProtectNode *);
size_t len_RobinProtectNode(const RobinProtectNode *);
int copy_RobinProtectNode(const RobinProtectNode *, RobinProtectNode *);


/*
RobinProtectNodes ::= SEQUENCE OF RobinProtectNode
*/

typedef struct RobinProtectNodes {
  uint32_t len;
  RobinProtectNode *val;
} RobinProtectNodes;

int enc_RobinProtectNodes(unsigned char *, size_t, const RobinProtectNodes *, size_t *);
int    dec_RobinProtectNodes(const unsigned char *, size_t, RobinProtectNodes *, size_t *);
void free_RobinProtectNodes  (RobinProtectNodes *);
size_t len_RobinProtectNodes(const RobinProtectNodes *);
int copy_RobinProtectNodes(const RobinProtectNodes *, RobinProtectNodes *);
RobinProtectNode * add_RobinProtectNode(RobinProtectNodes *);
int del_RobinProtectNode(RobinProtectNodes *, RobinProtectNode *);


/*
RobinGroupFlags ::= BIT STRING {
  external(0),
  readonly(1),
  donthave(2)
}
*/

typedef struct RobinGroupFlags {
  uint32_t external:1;
  uint32_t readonly:1;
  uint32_t donthave:1;
} RobinGroupFlags;


int enc_RobinGroupFlags(unsigned char *, size_t, const RobinGroupFlags *, size_t *);
int    dec_RobinGroupFlags(const unsigned char *, size_t, RobinGroupFlags *, size_t *);
void free_RobinGroupFlags  (RobinGroupFlags *);
size_t len_RobinGroupFlags(const RobinGroupFlags *);
int copy_RobinGroupFlags(const RobinGroupFlags *, RobinGroupFlags *);
unsigned RobinGroupFlags2int(RobinGroupFlags);
RobinGroupFlags int2RobinGroupFlags(unsigned);
const tbunits * asn1_RobinGroupFlags_units(void);

/*
RobinGroupRight ::= BIT STRING {
  display(0),
  ownership(1),
  membership(2),
  insert(3),
  delete(4)
}
*/

typedef struct RobinGroupRight {
  uint32_t display:1;
  uint32_t ownership:1;
  uint32_t membership:1;
  uint32_t insert:1;
  uint32_t delete:1;
} RobinGroupRight;


int enc_RobinGroupRight(unsigned char *, size_t, const RobinGroupRight *, size_t *);
int    dec_RobinGroupRight(const unsigned char *, size_t, RobinGroupRight *, size_t *);
void free_RobinGroupRight  (RobinGroupRight *);
size_t len_RobinGroupRight(const RobinGroupRight *);
int copy_RobinGroupRight(const RobinGroupRight *, RobinGroupRight *);
unsigned RobinGroupRight2int(RobinGroupRight);
RobinGroupRight int2RobinGroupRight(unsigned);
const tbunits * asn1_RobinGroupRight_units(void);

/*
RobinGroup ::= SEQUENCE {
  group[0]        RobinPrincipal,
  owner[1]        RobinPrincipal,
  public[2]       RobinGroupRight,
  private[3]      RobinGroupRight
}
*/

typedef struct RobinGroup {
  RobinPrincipal group;
  RobinPrincipal owner;
  RobinGroupRight public;
  RobinGroupRight private;
} RobinGroup;

int enc_RobinGroup(unsigned char *, size_t, const RobinGroup *, size_t *);
int    dec_RobinGroup(const unsigned char *, size_t, RobinGroup *, size_t *);
void free_RobinGroup  (RobinGroup *);
size_t len_RobinGroup(const RobinGroup *);
int copy_RobinGroup(const RobinGroup *, RobinGroup *);


/*
RobinGroups ::= SEQUENCE OF RobinGroup
*/

typedef struct RobinGroups {
  uint32_t len;
  RobinGroup *val;
} RobinGroups;

int enc_RobinGroups(unsigned char *, size_t, const RobinGroups *, size_t *);
int    dec_RobinGroups(const unsigned char *, size_t, RobinGroups *, size_t *);
void free_RobinGroups  (RobinGroups *);
size_t len_RobinGroups(const RobinGroups *);
int copy_RobinGroups(const RobinGroups *, RobinGroups *);
RobinGroup * add_RobinGroup(RobinGroups *);
int del_RobinGroup(RobinGroups *, RobinGroup *);


/*
RobinGraftFlags ::= BIT STRING {
  readonly(0),
  readwrite(1)
}
*/

typedef struct RobinGraftFlags {
  uint32_t readonly:1;
  uint32_t readwrite:1;
} RobinGraftFlags;


int enc_RobinGraftFlags(unsigned char *, size_t, const RobinGraftFlags *, size_t *);
int    dec_RobinGraftFlags(const unsigned char *, size_t, RobinGraftFlags *, size_t *);
void free_RobinGraftFlags  (RobinGraftFlags *);
size_t len_RobinGraftFlags(const RobinGraftFlags *);
int copy_RobinGraftFlags(const RobinGraftFlags *, RobinGraftFlags *);
unsigned RobinGraftFlags2int(RobinGraftFlags);
RobinGraftFlags int2RobinGraftFlags(unsigned);
const tbunits * asn1_RobinGraftFlags_units(void);

/*
RobinGraft ::= SEQUENCE {
  hdl[0]          RobinHandle,
  type[1]         ROBIN-TYPE,
  flags[2]        RobinGraftFlags,
  cell[3]         RobinCell OPTIONAL
}
*/

typedef struct RobinGraft {
  RobinHandle hdl;
  ROBIN_TYPE type;
  RobinGraftFlags flags;
  RobinCell *cell;
} RobinGraft;

int enc_RobinGraft(unsigned char *, size_t, const RobinGraft *, size_t *);
int    dec_RobinGraft(const unsigned char *, size_t, RobinGraft *, size_t *);
void free_RobinGraft  (RobinGraft *);
size_t len_RobinGraft(const RobinGraft *);
int copy_RobinGraft(const RobinGraft *, RobinGraft *);


/*
RobinTransFlags ::= BIT STRING {
  resize(0),
  append(1),
  readonly(2),
  abort(3)
}
*/

typedef struct RobinTransFlags {
  uint32_t resize:1;
  uint32_t append:1;
  uint32_t readonly:1;
  uint32_t abort:1;
} RobinTransFlags;


int enc_RobinTransFlags(unsigned char *, size_t, const RobinTransFlags *, size_t *);
int    dec_RobinTransFlags(const unsigned char *, size_t, RobinTransFlags *, size_t *);
void free_RobinTransFlags  (RobinTransFlags *);
size_t len_RobinTransFlags(const RobinTransFlags *);
int copy_RobinTransFlags(const RobinTransFlags *, RobinTransFlags *);
unsigned RobinTransFlags2int(RobinTransFlags);
RobinTransFlags int2RobinTransFlags(unsigned);
const tbunits * asn1_RobinTransFlags_units(void);

/*
RobinConFlags ::= BIT STRING {
  nosign(0),
  noencrypt(1),
  compress(2),
  shutdown(3),
  graceful(4)
}
*/

typedef struct RobinConFlags {
  uint32_t nosign:1;
  uint32_t noencrypt:1;
  uint32_t compress:1;
  uint32_t shutdown:1;
  uint32_t graceful:1;
} RobinConFlags;


int enc_RobinConFlags(unsigned char *, size_t, const RobinConFlags *, size_t *);
int    dec_RobinConFlags(const unsigned char *, size_t, RobinConFlags *, size_t *);
void free_RobinConFlags  (RobinConFlags *);
size_t len_RobinConFlags(const RobinConFlags *);
int copy_RobinConFlags(const RobinConFlags *, RobinConFlags *);
unsigned RobinConFlags2int(RobinConFlags);
RobinConFlags int2RobinConFlags(unsigned);
const tbunits * asn1_RobinConFlags_units(void);

/*
RobinServerPref ::= SEQUENCE {
  host[0]         RobinHost,
  rank[1]         INTEGER
}
*/

typedef struct RobinServerPref {
  RobinHost host;
  int32_t rank;
} RobinServerPref;

int enc_RobinServerPref(unsigned char *, size_t, const RobinServerPref *, size_t *);
int    dec_RobinServerPref(const unsigned char *, size_t, RobinServerPref *, size_t *);
void free_RobinServerPref  (RobinServerPref *);
size_t len_RobinServerPref(const RobinServerPref *);
int copy_RobinServerPref(const RobinServerPref *, RobinServerPref *);


/*
RobinServerPrefs ::= SEQUENCE OF RobinServerPref
*/

typedef struct RobinServerPrefs {
  uint32_t len;
  RobinServerPref *val;
} RobinServerPrefs;

int enc_RobinServerPrefs(unsigned char *, size_t, const RobinServerPrefs *, size_t *);
int    dec_RobinServerPrefs(const unsigned char *, size_t, RobinServerPrefs *, size_t *);
void free_RobinServerPrefs  (RobinServerPrefs *);
size_t len_RobinServerPrefs(const RobinServerPrefs *);
int copy_RobinServerPrefs(const RobinServerPrefs *, RobinServerPrefs *);
RobinServerPref * add_RobinServerPref(RobinServerPrefs *);
int del_RobinServerPref(RobinServerPrefs *, RobinServerPref *);


/*
RobinNodeFlags ::= BIT STRING {
  lock_attr(0),
  force(1),
  wipe(2)
}
*/

typedef struct RobinNodeFlags {
  uint32_t lock_attr:1;
  uint32_t force:1;
  uint32_t wipe:1;
} RobinNodeFlags;


int enc_RobinNodeFlags(unsigned char *, size_t, const RobinNodeFlags *, size_t *);
int    dec_RobinNodeFlags(const unsigned char *, size_t, RobinNodeFlags *, size_t *);
void free_RobinNodeFlags  (RobinNodeFlags *);
size_t len_RobinNodeFlags(const RobinNodeFlags *);
int copy_RobinNodeFlags(const RobinNodeFlags *, RobinNodeFlags *);
unsigned RobinNodeFlags2int(RobinNodeFlags);
RobinNodeFlags int2RobinNodeFlags(unsigned);
const tbunits * asn1_RobinNodeFlags_units(void);

/*
ROBIN-SYNCTYPE ::= INTEGER
*/

typedef enum ROBIN_SYNCTYPE {
  RSYNC_GETSUMS = 0,
  RSYNC_ADD = 1,
  RSYNC_COPY = 2,
  RSYNC_RUN = 3
} ROBIN_SYNCTYPE;

int enc_ROBIN_SYNCTYPE(unsigned char *, size_t, const ROBIN_SYNCTYPE *, size_t *);
int    dec_ROBIN_SYNCTYPE(const unsigned char *, size_t, ROBIN_SYNCTYPE *, size_t *);
void free_ROBIN_SYNCTYPE  (ROBIN_SYNCTYPE *);
size_t len_ROBIN_SYNCTYPE(const ROBIN_SYNCTYPE *);
int copy_ROBIN_SYNCTYPE(const ROBIN_SYNCTYPE *, ROBIN_SYNCTYPE *);


/*
RobinSyncFlags ::= BIT STRING {
  additional(0)
}
*/

typedef struct RobinSyncFlags {
  uint32_t additional:1;
} RobinSyncFlags;


int enc_RobinSyncFlags(unsigned char *, size_t, const RobinSyncFlags *, size_t *);
int    dec_RobinSyncFlags(const unsigned char *, size_t, RobinSyncFlags *, size_t *);
void free_RobinSyncFlags  (RobinSyncFlags *);
size_t len_RobinSyncFlags(const RobinSyncFlags *);
int copy_RobinSyncFlags(const RobinSyncFlags *, RobinSyncFlags *);
unsigned RobinSyncFlags2int(RobinSyncFlags);
RobinSyncFlags int2RobinSyncFlags(unsigned);
const tbunits * asn1_RobinSyncFlags_units(void);

/*
RobinSyncChecksum ::= SEQUENCE {
  offset[0]       INTEGER64,
  length[1]       INTEGER64,
  blksiz[2]       INTEGER64,
  weaksums[3]     RobinChecksums,
  hardsums[4]     RobinChecksums
}
*/

typedef struct RobinSyncChecksum {
  int64_t offset;
  int64_t length;
  int64_t blksiz;
  RobinChecksums weaksums;
  RobinChecksums hardsums;
} RobinSyncChecksum;

int enc_RobinSyncChecksum(unsigned char *, size_t, const RobinSyncChecksum *, size_t *);
int    dec_RobinSyncChecksum(const unsigned char *, size_t, RobinSyncChecksum *, size_t *);
void free_RobinSyncChecksum  (RobinSyncChecksum *);
size_t len_RobinSyncChecksum(const RobinSyncChecksum *);
int copy_RobinSyncChecksum(const RobinSyncChecksum *, RobinSyncChecksum *);


/*
RobinSyncCommand ::= SEQUENCE {
  command[0]      ROBIN-SYNCTYPE,
  offset[1]       INTEGER64,
  length[2]       INTEGER64,
  other[3]        INTEGER64,
  data[4]         RobinData
}
*/

typedef struct RobinSyncCommand {
  ROBIN_SYNCTYPE command;
  int64_t offset;
  int64_t length;
  int64_t other;
  RobinData data;
} RobinSyncCommand;

int enc_RobinSyncCommand(unsigned char *, size_t, const RobinSyncCommand *, size_t *);
int    dec_RobinSyncCommand(const unsigned char *, size_t, RobinSyncCommand *, size_t *);
void free_RobinSyncCommand  (RobinSyncCommand *);
size_t len_RobinSyncCommand(const RobinSyncCommand *);
int copy_RobinSyncCommand(const RobinSyncCommand *, RobinSyncCommand *);


/*
RobinSyncCommands ::= SEQUENCE OF RobinSyncCommand
*/

typedef struct RobinSyncCommands {
  uint32_t len;
  RobinSyncCommand *val;
} RobinSyncCommands;

int enc_RobinSyncCommands(unsigned char *, size_t, const RobinSyncCommands *, size_t *);
int    dec_RobinSyncCommands(const unsigned char *, size_t, RobinSyncCommands *, size_t *);
void free_RobinSyncCommands  (RobinSyncCommands *);
size_t len_RobinSyncCommands(const RobinSyncCommands *);
int copy_RobinSyncCommands(const RobinSyncCommands *, RobinSyncCommands *);
RobinSyncCommand * add_RobinSyncCommand(RobinSyncCommands *);
int del_RobinSyncCommand(RobinSyncCommands *, RobinSyncCommand *);


/*
RobinHeader ::= SEQUENCE {
  pvno[0]         INTEGER,
  xid[1]          ROBIN-UNSIGNED,
  user[2]         RobinPrincipal OPTIONAL
}
*/

typedef struct RobinHeader {
  int32_t pvno;
  ROBIN_UNSIGNED xid;
  RobinPrincipal *user;
} RobinHeader;

int enc_RobinHeader(unsigned char *, size_t, const RobinHeader *, size_t *);
int    dec_RobinHeader(const unsigned char *, size_t, RobinHeader *, size_t *);
void free_RobinHeader  (RobinHeader *);
size_t len_RobinHeader(const RobinHeader *);
int copy_RobinHeader(const RobinHeader *, RobinHeader *);


/*
RobinStatus ::= SEQUENCE {
  hdr[0]          RobinHeader,
  status[1]       INTEGER,
  rxid[2]         ROBIN-UNSIGNED
}
*/

typedef struct RobinStatus {
  RobinHeader hdr;
  int32_t status;
  ROBIN_UNSIGNED rxid;
} RobinStatus;

int enc_RobinStatus(unsigned char *, size_t, const RobinStatus *, size_t *);
int    dec_RobinStatus(const unsigned char *, size_t, RobinStatus *, size_t *);
void free_RobinStatus  (RobinStatus *);
size_t len_RobinStatus(const RobinStatus *);
int copy_RobinStatus(const RobinStatus *, RobinStatus *);


/*
ROBIN-GETROOT ::= [APPLICATION 1] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
} ROBIN_GETROOT;

int enc_ROBIN_GETROOT(unsigned char *, size_t, const ROBIN_GETROOT *, size_t *);
int    dec_ROBIN_GETROOT(const unsigned char *, size_t, ROBIN_GETROOT *, size_t *);
void free_ROBIN_GETROOT  (ROBIN_GETROOT *);
size_t len_ROBIN_GETROOT(const ROBIN_GETROOT *);
int copy_ROBIN_GETROOT(const ROBIN_GETROOT *, ROBIN_GETROOT *);


/*
ROBIN-GETROUTE ::= [APPLICATION 2] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  prefix[2]       INTEGER,
  limit[3]        INTEGER
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  int32_t prefix;
  int32_t limit;
} ROBIN_GETROUTE;

int enc_ROBIN_GETROUTE(unsigned char *, size_t, const ROBIN_GETROUTE *, size_t *);
int    dec_ROBIN_GETROUTE(const unsigned char *, size_t, ROBIN_GETROUTE *, size_t *);
void free_ROBIN_GETROUTE  (ROBIN_GETROUTE *);
size_t len_ROBIN_GETROUTE(const ROBIN_GETROUTE *);
int copy_ROBIN_GETROUTE(const ROBIN_GETROUTE *, ROBIN_GETROUTE *);


/*
ROBIN-GETDISK ::= [APPLICATION 3] SEQUENCE {
  hdr[0]          RobinHeader,
  disks[1]        RobinDisks OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisks *disks;
} ROBIN_GETDISK;

int enc_ROBIN_GETDISK(unsigned char *, size_t, const ROBIN_GETDISK *, size_t *);
int    dec_ROBIN_GETDISK(const unsigned char *, size_t, ROBIN_GETDISK *, size_t *);
void free_ROBIN_GETDISK  (ROBIN_GETDISK *);
size_t len_ROBIN_GETDISK(const ROBIN_GETDISK *);
int copy_ROBIN_GETDISK(const ROBIN_GETDISK *, ROBIN_GETDISK *);


/*
ROBIN-GETCLIENT ::= [APPLICATION 4] SEQUENCE {
  hdr[0]          RobinHeader,
  disks[1]        RobinDisks OPTIONAL,
  principals[2]   RobinPrincipals OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisks *disks;
  RobinPrincipals *principals;
} ROBIN_GETCLIENT;

int enc_ROBIN_GETCLIENT(unsigned char *, size_t, const ROBIN_GETCLIENT *, size_t *);
int    dec_ROBIN_GETCLIENT(const unsigned char *, size_t, ROBIN_GETCLIENT *, size_t *);
void free_ROBIN_GETCLIENT  (ROBIN_GETCLIENT *);
size_t len_ROBIN_GETCLIENT(const ROBIN_GETCLIENT *);
int copy_ROBIN_GETCLIENT(const ROBIN_GETCLIENT *, ROBIN_GETCLIENT *);


/*
ROBIN-GETOID ::= [APPLICATION 5] SEQUENCE {
  hdr[0]          RobinHeader,
  oid[1]          OBJECT IDENTIFIER {
  }
}
*/

typedef struct  {
  RobinHeader hdr;
  tb_oid oid;
} ROBIN_GETOID;

int enc_ROBIN_GETOID(unsigned char *, size_t, const ROBIN_GETOID *, size_t *);
int    dec_ROBIN_GETOID(const unsigned char *, size_t, ROBIN_GETOID *, size_t *);
void free_ROBIN_GETOID  (ROBIN_GETOID *);
size_t len_ROBIN_GETOID(const ROBIN_GETOID *);
int copy_ROBIN_GETOID(const ROBIN_GETOID *, ROBIN_GETOID *);


/*
ROBIN-SETOID ::= [APPLICATION 6] SEQUENCE {
  hdr[0]          RobinHeader,
  oid[1]          OBJECT IDENTIFIER {
  }
}
*/

typedef struct  {
  RobinHeader hdr;
  tb_oid oid;
} ROBIN_SETOID;

int enc_ROBIN_SETOID(unsigned char *, size_t, const ROBIN_SETOID *, size_t *);
int    dec_ROBIN_SETOID(const unsigned char *, size_t, ROBIN_SETOID *, size_t *);
void free_ROBIN_SETOID  (ROBIN_SETOID *);
size_t len_ROBIN_SETOID(const ROBIN_SETOID *);
int copy_ROBIN_SETOID(const ROBIN_SETOID *, ROBIN_SETOID *);


/*
ROBIN-GETLOCK ::= [APPLICATION 7] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  prefix[2]       INTEGER,
  principal[3]    RobinPrincipal OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  int32_t prefix;
  RobinPrincipal *principal;
} ROBIN_GETLOCK;

int enc_ROBIN_GETLOCK(unsigned char *, size_t, const ROBIN_GETLOCK *, size_t *);
int    dec_ROBIN_GETLOCK(const unsigned char *, size_t, ROBIN_GETLOCK *, size_t *);
void free_ROBIN_GETLOCK  (ROBIN_GETLOCK *);
size_t len_ROBIN_GETLOCK(const ROBIN_GETLOCK *);
int copy_ROBIN_GETLOCK(const ROBIN_GETLOCK *, ROBIN_GETLOCK *);


/*
ROBIN-GETACTION ::= [APPLICATION 8] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  prefix[2]       INTEGER,
  principal[3]    RobinPrincipal OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  int32_t prefix;
  RobinPrincipal *principal;
} ROBIN_GETACTION;

int enc_ROBIN_GETACTION(unsigned char *, size_t, const ROBIN_GETACTION *, size_t *);
int    dec_ROBIN_GETACTION(const unsigned char *, size_t, ROBIN_GETACTION *, size_t *);
void free_ROBIN_GETACTION  (ROBIN_GETACTION *);
size_t len_ROBIN_GETACTION(const ROBIN_GETACTION *);
int copy_ROBIN_GETACTION(const ROBIN_GETACTION *, ROBIN_GETACTION *);


/*
ROBIN-GETTRANS ::= [APPLICATION 9] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  prefix[2]       INTEGER,
  principal[3]    RobinPrincipal OPTIONAL,
  disk[4]         RobinDisk OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  int32_t prefix;
  RobinPrincipal *principal;
  RobinDisk *disk;
} ROBIN_GETTRANS;

int enc_ROBIN_GETTRANS(unsigned char *, size_t, const ROBIN_GETTRANS *, size_t *);
int    dec_ROBIN_GETTRANS(const unsigned char *, size_t, ROBIN_GETTRANS *, size_t *);
void free_ROBIN_GETTRANS  (ROBIN_GETTRANS *);
size_t len_ROBIN_GETTRANS(const ROBIN_GETTRANS *);
int copy_ROBIN_GETTRANS(const ROBIN_GETTRANS *, ROBIN_GETTRANS *);


/*
ROBIN-PING ::= [APPLICATION 10] SEQUENCE {
  hdr[0]          RobinHeader
}
*/

typedef struct  {
  RobinHeader hdr;
} ROBIN_PING;

int enc_ROBIN_PING(unsigned char *, size_t, const ROBIN_PING *, size_t *);
int    dec_ROBIN_PING(const unsigned char *, size_t, ROBIN_PING *, size_t *);
void free_ROBIN_PING  (ROBIN_PING *);
size_t len_ROBIN_PING(const ROBIN_PING *);
int copy_ROBIN_PING(const ROBIN_PING *, ROBIN_PING *);


/*
ROBIN-PONG ::= [APPLICATION 11] SEQUENCE {
  rep[0]          RobinStatus
}
*/

typedef struct  {
  RobinStatus rep;
} ROBIN_PONG;

int enc_ROBIN_PONG(unsigned char *, size_t, const ROBIN_PONG *, size_t *);
int    dec_ROBIN_PONG(const unsigned char *, size_t, ROBIN_PONG *, size_t *);
void free_ROBIN_PONG  (ROBIN_PONG *);
size_t len_ROBIN_PONG(const ROBIN_PONG *);
int copy_ROBIN_PONG(const ROBIN_PONG *, ROBIN_PONG *);


/*
ROBIN-SETCLIENTID ::= [APPLICATION 12] SEQUENCE {
  hdr[0]          RobinHeader,
  clientid[1]     OCTET STRING,
  identity[2]     OCTET STRING,
  verifier[3]     RobinEncryptionKey
}
*/

typedef struct  {
  RobinHeader hdr;
  tb_octet_string clientid;
  tb_octet_string identity;
  RobinEncryptionKey verifier;
} ROBIN_SETCLIENTID;

int enc_ROBIN_SETCLIENTID(unsigned char *, size_t, const ROBIN_SETCLIENTID *, size_t *);
int    dec_ROBIN_SETCLIENTID(const unsigned char *, size_t, ROBIN_SETCLIENTID *, size_t *);
void free_ROBIN_SETCLIENTID  (ROBIN_SETCLIENTID *);
size_t len_ROBIN_SETCLIENTID(const ROBIN_SETCLIENTID *);
int copy_ROBIN_SETCLIENTID(const ROBIN_SETCLIENTID *, ROBIN_SETCLIENTID *);


/*
ROBIN-SETCON ::= [APPLICATION 13] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinConFlags,
  addr[2]         RobinHostAddress OPTIONAL,
  prefs[3]        RobinServerPrefs OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinConFlags flags;
  RobinHostAddress *addr;
  RobinServerPrefs *prefs;
} ROBIN_SETCON;

int enc_ROBIN_SETCON(unsigned char *, size_t, const ROBIN_SETCON *, size_t *);
int    dec_ROBIN_SETCON(const unsigned char *, size_t, ROBIN_SETCON *, size_t *);
void free_ROBIN_SETCON  (ROBIN_SETCON *);
size_t len_ROBIN_SETCON(const ROBIN_SETCON *);
int copy_ROBIN_SETCON(const ROBIN_SETCON *, ROBIN_SETCON *);


/*
ROBIN-DISCONNECT ::= [APPLICATION 14] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinConFlags,
  time[2]         RobinTime
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinConFlags flags;
  RobinTime time;
} ROBIN_DISCONNECT;

int enc_ROBIN_DISCONNECT(unsigned char *, size_t, const ROBIN_DISCONNECT *, size_t *);
int    dec_ROBIN_DISCONNECT(const unsigned char *, size_t, ROBIN_DISCONNECT *, size_t *);
void free_ROBIN_DISCONNECT  (ROBIN_DISCONNECT *);
size_t len_ROBIN_DISCONNECT(const ROBIN_DISCONNECT *);
int copy_ROBIN_DISCONNECT(const ROBIN_DISCONNECT *, ROBIN_DISCONNECT *);


/*
ROBIN-REFRESH ::= [APPLICATION 15] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle *hdl;
} ROBIN_REFRESH;

int enc_ROBIN_REFRESH(unsigned char *, size_t, const ROBIN_REFRESH *, size_t *);
int    dec_ROBIN_REFRESH(const unsigned char *, size_t, ROBIN_REFRESH *, size_t *);
void free_ROBIN_REFRESH  (ROBIN_REFRESH *);
size_t len_ROBIN_REFRESH(const ROBIN_REFRESH *);
int copy_ROBIN_REFRESH(const ROBIN_REFRESH *, ROBIN_REFRESH *);


/*
ROBIN-STATUS ::= [APPLICATION 20] SEQUENCE {
  rep[0]          RobinStatus
}
*/

typedef struct  {
  RobinStatus rep;
} ROBIN_STATUS;

int enc_ROBIN_STATUS(unsigned char *, size_t, const ROBIN_STATUS *, size_t *);
int    dec_ROBIN_STATUS(const unsigned char *, size_t, ROBIN_STATUS *, size_t *);
void free_ROBIN_STATUS  (ROBIN_STATUS *);
size_t len_ROBIN_STATUS(const ROBIN_STATUS *);
int copy_ROBIN_STATUS(const ROBIN_STATUS *, ROBIN_STATUS *);


/*
ROBIN-STATUSHDL ::= [APPLICATION 21] SEQUENCE {
  rep[0]          RobinStatus,
  hdl[1]          RobinHandle,
  lock[2]         RobinLock OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinHandle hdl;
  RobinLock *lock;
} ROBIN_STATUSHDL;

int enc_ROBIN_STATUSHDL(unsigned char *, size_t, const ROBIN_STATUSHDL *, size_t *);
int    dec_ROBIN_STATUSHDL(const unsigned char *, size_t, ROBIN_STATUSHDL *, size_t *);
void free_ROBIN_STATUSHDL  (ROBIN_STATUSHDL *);
size_t len_ROBIN_STATUSHDL(const ROBIN_STATUSHDL *);
int copy_ROBIN_STATUSHDL(const ROBIN_STATUSHDL *, ROBIN_STATUSHDL *);


/*
ROBIN-STATUSHDLSUM ::= [APPLICATION 22] SEQUENCE {
  rep[0]          RobinStatus,
  hdl[1]          RobinHandle,
  sum[2]          RobinChecksum,
  lock[3]         RobinLock OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinHandle hdl;
  RobinChecksum sum;
  RobinLock *lock;
} ROBIN_STATUSHDLSUM;

int enc_ROBIN_STATUSHDLSUM(unsigned char *, size_t, const ROBIN_STATUSHDLSUM *, size_t *);
int    dec_ROBIN_STATUSHDLSUM(const unsigned char *, size_t, ROBIN_STATUSHDLSUM *, size_t *);
void free_ROBIN_STATUSHDLSUM  (ROBIN_STATUSHDLSUM *);
size_t len_ROBIN_STATUSHDLSUM(const ROBIN_STATUSHDLSUM *);
int copy_ROBIN_STATUSHDLSUM(const ROBIN_STATUSHDLSUM *, ROBIN_STATUSHDLSUM *);


/*
ROBIN-STATUSROUTE ::= [APPLICATION 23] SEQUENCE {
  rep[0]          RobinStatus,
  hdl[1]          RobinHandle,
  prefix[2]       INTEGER,
  rtype[3]        ROBIN-ROUTETYPE,
  ntype[4]        ROBIN-TYPE,
  flags[5]        RobinRouterFlags,
  ttl[6]          INTEGER,
  sum[7]          RobinChecksum OPTIONAL,
  disk[8]         RobinDisk OPTIONAL,
  size[9]         INTEGER64,
  atime[10]       RobinTime OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinHandle hdl;
  int32_t prefix;
  ROBIN_ROUTETYPE rtype;
  ROBIN_TYPE ntype;
  RobinRouterFlags flags;
  int32_t ttl;
  RobinChecksum *sum;
  RobinDisk *disk;
  int64_t size;
  RobinTime *atime;
} ROBIN_STATUSROUTE;

int enc_ROBIN_STATUSROUTE(unsigned char *, size_t, const ROBIN_STATUSROUTE *, size_t *);
int    dec_ROBIN_STATUSROUTE(const unsigned char *, size_t, ROBIN_STATUSROUTE *, size_t *);
void free_ROBIN_STATUSROUTE  (ROBIN_STATUSROUTE *);
size_t len_ROBIN_STATUSROUTE(const ROBIN_STATUSROUTE *);
int copy_ROBIN_STATUSROUTE(const ROBIN_STATUSROUTE *, ROBIN_STATUSROUTE *);


/*
ROBIN-STATUSLOCK ::= [APPLICATION 24] SEQUENCE {
  rep[0]          RobinStatus,
  lock[1]         RobinLock OPTIONAL,
  hosts[2]        RobinHosts OPTIONAL,
  tokens[3]       RobinTokens OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinLock *lock;
  RobinHosts *hosts;
  RobinTokens *tokens;
} ROBIN_STATUSLOCK;

int enc_ROBIN_STATUSLOCK(unsigned char *, size_t, const ROBIN_STATUSLOCK *, size_t *);
int    dec_ROBIN_STATUSLOCK(const unsigned char *, size_t, ROBIN_STATUSLOCK *, size_t *);
void free_ROBIN_STATUSLOCK  (ROBIN_STATUSLOCK *);
size_t len_ROBIN_STATUSLOCK(const ROBIN_STATUSLOCK *);
int copy_ROBIN_STATUSLOCK(const ROBIN_STATUSLOCK *, ROBIN_STATUSLOCK *);


/*
ROBIN-STATUSINFO ::= [APPLICATION 25] SEQUENCE {
  rep[0]          RobinStatus,
  hdl[1]          RobinHandle,
  vhdl[2]         RobinHandle OPTIONAL,
  attr[3]         RobinAttributes,
  sum[4]          RobinChecksum,
  lock[5]         RobinLock OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinHandle hdl;
  RobinHandle *vhdl;
  RobinAttributes attr;
  RobinChecksum sum;
  RobinLock *lock;
} ROBIN_STATUSINFO;

int enc_ROBIN_STATUSINFO(unsigned char *, size_t, const ROBIN_STATUSINFO *, size_t *);
int    dec_ROBIN_STATUSINFO(const unsigned char *, size_t, ROBIN_STATUSINFO *, size_t *);
void free_ROBIN_STATUSINFO  (ROBIN_STATUSINFO *);
size_t len_ROBIN_STATUSINFO(const ROBIN_STATUSINFO *);
int copy_ROBIN_STATUSINFO(const ROBIN_STATUSINFO *, ROBIN_STATUSINFO *);


/*
ROBIN-STATUSACL ::= [APPLICATION 26] SEQUENCE {
  rep[0]          RobinStatus,
  acl[1]          RobinRightsList,
  lock[2]         RobinLock OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinRightsList acl;
  RobinLock *lock;
} ROBIN_STATUSACL;

int enc_ROBIN_STATUSACL(unsigned char *, size_t, const ROBIN_STATUSACL *, size_t *);
int    dec_ROBIN_STATUSACL(const unsigned char *, size_t, ROBIN_STATUSACL *, size_t *);
void free_ROBIN_STATUSACL  (ROBIN_STATUSACL *);
size_t len_ROBIN_STATUSACL(const ROBIN_STATUSACL *);
int copy_ROBIN_STATUSACL(const ROBIN_STATUSACL *, ROBIN_STATUSACL *);


/*
ROBIN-STATUSDATA ::= [APPLICATION 27] SEQUENCE {
  rep[0]          RobinStatus,
  data[1]         OCTET STRING
}
*/

typedef struct  {
  RobinStatus rep;
  tb_octet_string data;
} ROBIN_STATUSDATA;

int enc_ROBIN_STATUSDATA(unsigned char *, size_t, const ROBIN_STATUSDATA *, size_t *);
int    dec_ROBIN_STATUSDATA(const unsigned char *, size_t, ROBIN_STATUSDATA *, size_t *);
void free_ROBIN_STATUSDATA  (ROBIN_STATUSDATA *);
size_t len_ROBIN_STATUSDATA(const ROBIN_STATUSDATA *);
int copy_ROBIN_STATUSDATA(const ROBIN_STATUSDATA *, ROBIN_STATUSDATA *);


/*
ROBIN-STATUSDIRENT ::= [APPLICATION 28] SEQUENCE {
  rep[0]          RobinStatus,
  entries[1]      RobinDirentries,
  lock[2]         RobinLock OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinDirentries entries;
  RobinLock *lock;
} ROBIN_STATUSDIRENT;

int enc_ROBIN_STATUSDIRENT(unsigned char *, size_t, const ROBIN_STATUSDIRENT *, size_t *);
int    dec_ROBIN_STATUSDIRENT(const unsigned char *, size_t, ROBIN_STATUSDIRENT *, size_t *);
void free_ROBIN_STATUSDIRENT  (ROBIN_STATUSDIRENT *);
size_t len_ROBIN_STATUSDIRENT(const ROBIN_STATUSDIRENT *);
int copy_ROBIN_STATUSDIRENT(const ROBIN_STATUSDIRENT *, ROBIN_STATUSDIRENT *);


/*
ROBIN-STATUSTOKEN ::= [APPLICATION 29] SEQUENCE {
  rep[0]          RobinStatus,
  token[1]        RobinToken
}
*/

typedef struct  {
  RobinStatus rep;
  RobinToken token;
} ROBIN_STATUSTOKEN;

int enc_ROBIN_STATUSTOKEN(unsigned char *, size_t, const ROBIN_STATUSTOKEN *, size_t *);
int    dec_ROBIN_STATUSTOKEN(const unsigned char *, size_t, ROBIN_STATUSTOKEN *, size_t *);
void free_ROBIN_STATUSTOKEN  (ROBIN_STATUSTOKEN *);
size_t len_ROBIN_STATUSTOKEN(const ROBIN_STATUSTOKEN *);
int copy_ROBIN_STATUSTOKEN(const ROBIN_STATUSTOKEN *, ROBIN_STATUSTOKEN *);


/*
ROBIN-STATUSDISK ::= [APPLICATION 30] SEQUENCE {
  rep[0]          RobinStatus,
  disk[1]         RobinDisk,
  usedspace[2]    INTEGER64,
  usednodes[3]    INTEGER64,
  freespace[4]    INTEGER64,
  freenodes[5]    INTEGER64,
  rttlatency[6]   RobinTime,
  rbandwidth[7]   INTEGER64,
  wbandwidth[8]   INTEGER64,
  flags[9]        RobinDiskFlags
}
*/

typedef struct  {
  RobinStatus rep;
  RobinDisk disk;
  int64_t usedspace;
  int64_t usednodes;
  int64_t freespace;
  int64_t freenodes;
  RobinTime rttlatency;
  int64_t rbandwidth;
  int64_t wbandwidth;
  RobinDiskFlags flags;
} ROBIN_STATUSDISK;

int enc_ROBIN_STATUSDISK(unsigned char *, size_t, const ROBIN_STATUSDISK *, size_t *);
int    dec_ROBIN_STATUSDISK(const unsigned char *, size_t, ROBIN_STATUSDISK *, size_t *);
void free_ROBIN_STATUSDISK  (ROBIN_STATUSDISK *);
size_t len_ROBIN_STATUSDISK(const ROBIN_STATUSDISK *);
int copy_ROBIN_STATUSDISK(const ROBIN_STATUSDISK *, ROBIN_STATUSDISK *);


/*
ROBIN-STATUSHOST ::= [APPLICATION 31] SEQUENCE {
  rep[0]          RobinStatus,
  host[1]         RobinHost,
  clientid[2]     OCTET STRING,
  principals[3]   RobinPrincipals
}
*/

typedef struct  {
  RobinStatus rep;
  RobinHost host;
  tb_octet_string clientid;
  RobinPrincipals principals;
} ROBIN_STATUSHOST;

int enc_ROBIN_STATUSHOST(unsigned char *, size_t, const ROBIN_STATUSHOST *, size_t *);
int    dec_ROBIN_STATUSHOST(const unsigned char *, size_t, ROBIN_STATUSHOST *, size_t *);
void free_ROBIN_STATUSHOST  (ROBIN_STATUSHOST *);
size_t len_ROBIN_STATUSHOST(const ROBIN_STATUSHOST *);
int copy_ROBIN_STATUSHOST(const ROBIN_STATUSHOST *, ROBIN_STATUSHOST *);


/*
ROBIN-STATUSGROUP ::= [APPLICATION 32] SEQUENCE {
  rep[0]          RobinStatus,
  group[1]        RobinPrincipal,
  owner[2]        RobinPrincipal OPTIONAL,
  public[3]       RobinGroupRight OPTIONAL,
  private[4]      RobinGroupRight OPTIONAL,
  users[5]        RobinPrincipals OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinPrincipal group;
  RobinPrincipal *owner;
  RobinGroupRight *public;
  RobinGroupRight *private;
  RobinPrincipals *users;
} ROBIN_STATUSGROUP;

int enc_ROBIN_STATUSGROUP(unsigned char *, size_t, const ROBIN_STATUSGROUP *, size_t *);
int    dec_ROBIN_STATUSGROUP(const unsigned char *, size_t, ROBIN_STATUSGROUP *, size_t *);
void free_ROBIN_STATUSGROUP  (ROBIN_STATUSGROUP *);
size_t len_ROBIN_STATUSGROUP(const ROBIN_STATUSGROUP *);
int copy_ROBIN_STATUSGROUP(const ROBIN_STATUSGROUP *, ROBIN_STATUSGROUP *);


/*
ROBIN-STATUSOID ::= [APPLICATION 33] SEQUENCE {
  rep[0]          RobinStatus,
  data[1]         OCTET STRING
}
*/

typedef struct  {
  RobinStatus rep;
  tb_octet_string data;
} ROBIN_STATUSOID;

int enc_ROBIN_STATUSOID(unsigned char *, size_t, const ROBIN_STATUSOID *, size_t *);
int    dec_ROBIN_STATUSOID(const unsigned char *, size_t, ROBIN_STATUSOID *, size_t *);
void free_ROBIN_STATUSOID  (ROBIN_STATUSOID *);
size_t len_ROBIN_STATUSOID(const ROBIN_STATUSOID *);
int copy_ROBIN_STATUSOID(const ROBIN_STATUSOID *, ROBIN_STATUSOID *);


/*
ROBIN-STATUSPROTECT ::= [APPLICATION 34] SEQUENCE {
  rep[0]          RobinStatus,
  rules[1]        RobinProtectNodes
}
*/

typedef struct  {
  RobinStatus rep;
  RobinProtectNodes rules;
} ROBIN_STATUSPROTECT;

int enc_ROBIN_STATUSPROTECT(unsigned char *, size_t, const ROBIN_STATUSPROTECT *, size_t *);
int    dec_ROBIN_STATUSPROTECT(const unsigned char *, size_t, ROBIN_STATUSPROTECT *, size_t *);
void free_ROBIN_STATUSPROTECT  (ROBIN_STATUSPROTECT *);
size_t len_ROBIN_STATUSPROTECT(const ROBIN_STATUSPROTECT *);
int copy_ROBIN_STATUSPROTECT(const ROBIN_STATUSPROTECT *, ROBIN_STATUSPROTECT *);


/*
ROBIN-STATUSSYNC ::= [APPLICATION 35] SEQUENCE {
  rep[0]          RobinStatus,
  syncsum[1]      RobinSyncChecksum OPTIONAL
}
*/

typedef struct  {
  RobinStatus rep;
  RobinSyncChecksum *syncsum;
} ROBIN_STATUSSYNC;

int enc_ROBIN_STATUSSYNC(unsigned char *, size_t, const ROBIN_STATUSSYNC *, size_t *);
int    dec_ROBIN_STATUSSYNC(const unsigned char *, size_t, ROBIN_STATUSSYNC *, size_t *);
void free_ROBIN_STATUSSYNC  (ROBIN_STATUSSYNC *);
size_t len_ROBIN_STATUSSYNC(const ROBIN_STATUSSYNC *);
int copy_ROBIN_STATUSSYNC(const ROBIN_STATUSSYNC *, ROBIN_STATUSSYNC *);


/*
ROBIN-MKNODE ::= [APPLICATION 40] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle OPTIONAL,
  attr[4]         RobinAttributes,
  sum[5]          RobinChecksum OPTIONAL,
  lock[6]         ROBIN-LOCKTYPE OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle *hdl;
  RobinAttributes attr;
  RobinChecksum *sum;
  ROBIN_LOCKTYPE *lock;
} ROBIN_MKNODE;

int enc_ROBIN_MKNODE(unsigned char *, size_t, const ROBIN_MKNODE *, size_t *);
int    dec_ROBIN_MKNODE(const unsigned char *, size_t, ROBIN_MKNODE *, size_t *);
void free_ROBIN_MKNODE  (ROBIN_MKNODE *);
size_t len_ROBIN_MKNODE(const ROBIN_MKNODE *);
int copy_ROBIN_MKNODE(const ROBIN_MKNODE *, ROBIN_MKNODE *);


/*
ROBIN-MKSYM ::= [APPLICATION 41] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  attr[4]         RobinAttributes,
  dest[5]         RobinFilename,
  lock[6]         ROBIN-LOCKTYPE OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  RobinAttributes attr;
  RobinFilename dest;
  ROBIN_LOCKTYPE *lock;
} ROBIN_MKSYM;

int enc_ROBIN_MKSYM(unsigned char *, size_t, const ROBIN_MKSYM *, size_t *);
int    dec_ROBIN_MKSYM(const unsigned char *, size_t, ROBIN_MKSYM *, size_t *);
void free_ROBIN_MKSYM  (ROBIN_MKSYM *);
size_t len_ROBIN_MKSYM(const ROBIN_MKSYM *);
int copy_ROBIN_MKSYM(const ROBIN_MKSYM *, ROBIN_MKSYM *);


/*
ROBIN-OPEN ::= [APPLICATION 42] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  lock[4]         ROBIN-LOCKTYPE OPTIONAL,
  disk[5]         RobinDisk OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  ROBIN_LOCKTYPE *lock;
  RobinDisk *disk;
} ROBIN_OPEN;

int enc_ROBIN_OPEN(unsigned char *, size_t, const ROBIN_OPEN *, size_t *);
int    dec_ROBIN_OPEN(const unsigned char *, size_t, ROBIN_OPEN *, size_t *);
void free_ROBIN_OPEN  (ROBIN_OPEN *);
size_t len_ROBIN_OPEN(const ROBIN_OPEN *);
int copy_ROBIN_OPEN(const ROBIN_OPEN *, ROBIN_OPEN *);


/*
ROBIN-UNLOCK ::= [APPLICATION 43] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  lock[4]         ROBIN-LOCKTYPE OPTIONAL,
  expiry[5]       RobinTime OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  ROBIN_LOCKTYPE *lock;
  RobinTime *expiry;
} ROBIN_UNLOCK;

int enc_ROBIN_UNLOCK(unsigned char *, size_t, const ROBIN_UNLOCK *, size_t *);
int    dec_ROBIN_UNLOCK(const unsigned char *, size_t, ROBIN_UNLOCK *, size_t *);
void free_ROBIN_UNLOCK  (ROBIN_UNLOCK *);
size_t len_ROBIN_UNLOCK(const ROBIN_UNLOCK *);
int copy_ROBIN_UNLOCK(const ROBIN_UNLOCK *, ROBIN_UNLOCK *);


/*
ROBIN-GETATTR ::= [APPLICATION 44] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
} ROBIN_GETATTR;

int enc_ROBIN_GETATTR(unsigned char *, size_t, const ROBIN_GETATTR *, size_t *);
int    dec_ROBIN_GETATTR(const unsigned char *, size_t, ROBIN_GETATTR *, size_t *);
void free_ROBIN_GETATTR  (ROBIN_GETATTR *);
size_t len_ROBIN_GETATTR(const ROBIN_GETATTR *);
int copy_ROBIN_GETATTR(const ROBIN_GETATTR *, ROBIN_GETATTR *);


/*
ROBIN-PUTATTR ::= [APPLICATION 45] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  attr[4]         RobinAttributes,
  sum[5]          RobinChecksum OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  RobinAttributes attr;
  RobinChecksum *sum;
} ROBIN_PUTATTR;

int enc_ROBIN_PUTATTR(unsigned char *, size_t, const ROBIN_PUTATTR *, size_t *);
int    dec_ROBIN_PUTATTR(const unsigned char *, size_t, ROBIN_PUTATTR *, size_t *);
void free_ROBIN_PUTATTR  (ROBIN_PUTATTR *);
size_t len_ROBIN_PUTATTR(const ROBIN_PUTATTR *);
int copy_ROBIN_PUTATTR(const ROBIN_PUTATTR *, ROBIN_PUTATTR *);


/*
ROBIN-GETACL ::= [APPLICATION 46] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  principal[4]    RobinPrincipal OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  RobinPrincipal *principal;
} ROBIN_GETACL;

int enc_ROBIN_GETACL(unsigned char *, size_t, const ROBIN_GETACL *, size_t *);
int    dec_ROBIN_GETACL(const unsigned char *, size_t, ROBIN_GETACL *, size_t *);
void free_ROBIN_GETACL  (ROBIN_GETACL *);
size_t len_ROBIN_GETACL(const ROBIN_GETACL *);
int copy_ROBIN_GETACL(const ROBIN_GETACL *, ROBIN_GETACL *);


/*
ROBIN-PUTACL ::= [APPLICATION 47] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  append[4]       RobinRightsList OPTIONAL,
  change[5]       RobinRightsList OPTIONAL,
  delete[6]       RobinRightsList OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  RobinRightsList *append;
  RobinRightsList *change;
  RobinRightsList *delete;
} ROBIN_PUTACL;

int enc_ROBIN_PUTACL(unsigned char *, size_t, const ROBIN_PUTACL *, size_t *);
int    dec_ROBIN_PUTACL(const unsigned char *, size_t, ROBIN_PUTACL *, size_t *);
void free_ROBIN_PUTACL  (ROBIN_PUTACL *);
size_t len_ROBIN_PUTACL(const ROBIN_PUTACL *);
int copy_ROBIN_PUTACL(const ROBIN_PUTACL *, ROBIN_PUTACL *);


/*
ROBIN-READ ::= [APPLICATION 50] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  offset[2]       INTEGER64,
  length[3]       INTEGER64,
  token[4]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  int64_t offset;
  int64_t length;
  RobinToken *token;
} ROBIN_READ;

int enc_ROBIN_READ(unsigned char *, size_t, const ROBIN_READ *, size_t *);
int    dec_ROBIN_READ(const unsigned char *, size_t, ROBIN_READ *, size_t *);
void free_ROBIN_READ  (ROBIN_READ *);
size_t len_ROBIN_READ(const ROBIN_READ *);
int copy_ROBIN_READ(const ROBIN_READ *, ROBIN_READ *);


/*
ROBIN-WRITE ::= [APPLICATION 51] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  offset[2]       INTEGER64,
  length[3]       INTEGER64,
  data[4]         OCTET STRING,
  sum[5]          RobinChecksum OPTIONAL,
  token[6]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  int64_t offset;
  int64_t length;
  tb_octet_string data;
  RobinChecksum *sum;
  RobinToken *token;
} ROBIN_WRITE;

int enc_ROBIN_WRITE(unsigned char *, size_t, const ROBIN_WRITE *, size_t *);
int    dec_ROBIN_WRITE(const unsigned char *, size_t, ROBIN_WRITE *, size_t *);
void free_ROBIN_WRITE  (ROBIN_WRITE *);
size_t len_ROBIN_WRITE(const ROBIN_WRITE *);
int copy_ROBIN_WRITE(const ROBIN_WRITE *, ROBIN_WRITE *);


/*
ROBIN-APPEND ::= [APPLICATION 52] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  data[2]         OCTET STRING,
  token[3]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  tb_octet_string data;
  RobinToken *token;
} ROBIN_APPEND;

int enc_ROBIN_APPEND(unsigned char *, size_t, const ROBIN_APPEND *, size_t *);
int    dec_ROBIN_APPEND(const unsigned char *, size_t, ROBIN_APPEND *, size_t *);
void free_ROBIN_APPEND  (ROBIN_APPEND *);
size_t len_ROBIN_APPEND(const ROBIN_APPEND *);
int copy_ROBIN_APPEND(const ROBIN_APPEND *, ROBIN_APPEND *);


/*
ROBIN-TRANS-START ::= [APPLICATION 53] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinTransFlags,
  hdl[2]          RobinHandle,
  offset[3]       INTEGER64,
  length[4]       INTEGER64,
  token[5]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinTransFlags flags;
  RobinHandle hdl;
  int64_t offset;
  int64_t length;
  RobinToken *token;
} ROBIN_TRANS_START;

int enc_ROBIN_TRANS_START(unsigned char *, size_t, const ROBIN_TRANS_START *, size_t *);
int    dec_ROBIN_TRANS_START(const unsigned char *, size_t, ROBIN_TRANS_START *, size_t *);
void free_ROBIN_TRANS_START  (ROBIN_TRANS_START *);
size_t len_ROBIN_TRANS_START(const ROBIN_TRANS_START *);
int copy_ROBIN_TRANS_START(const ROBIN_TRANS_START *, ROBIN_TRANS_START *);


/*
ROBIN-TRANS-WRITE ::= [APPLICATION 54] SEQUENCE {
  hdr[0]          RobinHeader,
  token[1]        RobinToken,
  offset[2]       INTEGER64,
  data[3]         OCTET STRING
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinToken token;
  int64_t offset;
  tb_octet_string data;
} ROBIN_TRANS_WRITE;

int enc_ROBIN_TRANS_WRITE(unsigned char *, size_t, const ROBIN_TRANS_WRITE *, size_t *);
int    dec_ROBIN_TRANS_WRITE(const unsigned char *, size_t, ROBIN_TRANS_WRITE *, size_t *);
void free_ROBIN_TRANS_WRITE  (ROBIN_TRANS_WRITE *);
size_t len_ROBIN_TRANS_WRITE(const ROBIN_TRANS_WRITE *);
int copy_ROBIN_TRANS_WRITE(const ROBIN_TRANS_WRITE *, ROBIN_TRANS_WRITE *);


/*
ROBIN-TRANS-APPEND ::= [APPLICATION 55] SEQUENCE {
  hdr[0]          RobinHeader,
  token[1]        RobinToken,
  data[2]         OCTET STRING
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinToken token;
  tb_octet_string data;
} ROBIN_TRANS_APPEND;

int enc_ROBIN_TRANS_APPEND(unsigned char *, size_t, const ROBIN_TRANS_APPEND *, size_t *);
int    dec_ROBIN_TRANS_APPEND(const unsigned char *, size_t, ROBIN_TRANS_APPEND *, size_t *);
void free_ROBIN_TRANS_APPEND  (ROBIN_TRANS_APPEND *);
size_t len_ROBIN_TRANS_APPEND(const ROBIN_TRANS_APPEND *);
int copy_ROBIN_TRANS_APPEND(const ROBIN_TRANS_APPEND *, ROBIN_TRANS_APPEND *);


/*
ROBIN-TRANS-READ ::= [APPLICATION 56] SEQUENCE {
  hdr[0]          RobinHeader,
  token[1]        RobinToken,
  offset[2]       INTEGER64,
  length[3]       INTEGER64
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinToken token;
  int64_t offset;
  int64_t length;
} ROBIN_TRANS_READ;

int enc_ROBIN_TRANS_READ(unsigned char *, size_t, const ROBIN_TRANS_READ *, size_t *);
int    dec_ROBIN_TRANS_READ(const unsigned char *, size_t, ROBIN_TRANS_READ *, size_t *);
void free_ROBIN_TRANS_READ  (ROBIN_TRANS_READ *);
size_t len_ROBIN_TRANS_READ(const ROBIN_TRANS_READ *);
int copy_ROBIN_TRANS_READ(const ROBIN_TRANS_READ *, ROBIN_TRANS_READ *);


/*
ROBIN-TRANS-FINISH ::= [APPLICATION 57] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinTransFlags,
  token[2]        RobinToken,
  sum[3]          RobinChecksum OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinTransFlags flags;
  RobinToken token;
  RobinChecksum *sum;
} ROBIN_TRANS_FINISH;

int enc_ROBIN_TRANS_FINISH(unsigned char *, size_t, const ROBIN_TRANS_FINISH *, size_t *);
int    dec_ROBIN_TRANS_FINISH(const unsigned char *, size_t, ROBIN_TRANS_FINISH *, size_t *);
void free_ROBIN_TRANS_FINISH  (ROBIN_TRANS_FINISH *);
size_t len_ROBIN_TRANS_FINISH(const ROBIN_TRANS_FINISH *);
int copy_ROBIN_TRANS_FINISH(const ROBIN_TRANS_FINISH *, ROBIN_TRANS_FINISH *);


/*
ROBIN-TRANS-ABORT ::= [APPLICATION 58] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinTransFlags,
  token[2]        RobinToken,
  txid[3]         OCTET STRING OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinTransFlags flags;
  RobinToken token;
  tb_octet_string *txid;
} ROBIN_TRANS_ABORT;

int enc_ROBIN_TRANS_ABORT(unsigned char *, size_t, const ROBIN_TRANS_ABORT *, size_t *);
int    dec_ROBIN_TRANS_ABORT(const unsigned char *, size_t, ROBIN_TRANS_ABORT *, size_t *);
void free_ROBIN_TRANS_ABORT  (ROBIN_TRANS_ABORT *);
size_t len_ROBIN_TRANS_ABORT(const ROBIN_TRANS_ABORT *);
int copy_ROBIN_TRANS_ABORT(const ROBIN_TRANS_ABORT *, ROBIN_TRANS_ABORT *);


/*
ROBIN-TRANS-SYNC ::= [APPLICATION 59] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinTransFlags,
  token[2]        RobinToken,
  sflags[3]       RobinSyncFlags,
  hardsumtype[4]  ROBIN-CKSUMTYPE,
  cmds[5]         RobinSyncCommands
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinTransFlags flags;
  RobinToken token;
  RobinSyncFlags sflags;
  ROBIN_CKSUMTYPE hardsumtype;
  RobinSyncCommands cmds;
} ROBIN_TRANS_SYNC;

int enc_ROBIN_TRANS_SYNC(unsigned char *, size_t, const ROBIN_TRANS_SYNC *, size_t *);
int    dec_ROBIN_TRANS_SYNC(const unsigned char *, size_t, ROBIN_TRANS_SYNC *, size_t *);
void free_ROBIN_TRANS_SYNC  (ROBIN_TRANS_SYNC *);
size_t len_ROBIN_TRANS_SYNC(const ROBIN_TRANS_SYNC *);
int copy_ROBIN_TRANS_SYNC(const ROBIN_TRANS_SYNC *, ROBIN_TRANS_SYNC *);


/*
ROBIN-NODE-PUT ::= [APPLICATION 60] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  type[3]         ROBIN-TYPE,
  size[4]         INTEGER64,
  sum[5]          RobinChecksum OPTIONAL,
  disk[6]         RobinDisk OPTIONAL,
  token[7]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  ROBIN_TYPE type;
  int64_t size;
  RobinChecksum *sum;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_PUT;

int enc_ROBIN_NODE_PUT(unsigned char *, size_t, const ROBIN_NODE_PUT *, size_t *);
int    dec_ROBIN_NODE_PUT(const unsigned char *, size_t, ROBIN_NODE_PUT *, size_t *);
void free_ROBIN_NODE_PUT  (ROBIN_NODE_PUT *);
size_t len_ROBIN_NODE_PUT(const ROBIN_NODE_PUT *);
int copy_ROBIN_NODE_PUT(const ROBIN_NODE_PUT *, ROBIN_NODE_PUT *);


/*
ROBIN-NODE-DEL ::= [APPLICATION 61] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  disk[3]         RobinDisk OPTIONAL,
  token[4]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_DEL;

int enc_ROBIN_NODE_DEL(unsigned char *, size_t, const ROBIN_NODE_DEL *, size_t *);
int    dec_ROBIN_NODE_DEL(const unsigned char *, size_t, ROBIN_NODE_DEL *, size_t *);
void free_ROBIN_NODE_DEL  (ROBIN_NODE_DEL *);
size_t len_ROBIN_NODE_DEL(const ROBIN_NODE_DEL *);
int copy_ROBIN_NODE_DEL(const ROBIN_NODE_DEL *, ROBIN_NODE_DEL *);


/*
ROBIN-NODE-COW ::= [APPLICATION 62] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  nhdl[3]         RobinHandle,
  disk[4]         RobinDisk OPTIONAL,
  token[5]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  RobinHandle nhdl;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_COW;

int enc_ROBIN_NODE_COW(unsigned char *, size_t, const ROBIN_NODE_COW *, size_t *);
int    dec_ROBIN_NODE_COW(const unsigned char *, size_t, ROBIN_NODE_COW *, size_t *);
void free_ROBIN_NODE_COW  (ROBIN_NODE_COW *);
size_t len_ROBIN_NODE_COW(const ROBIN_NODE_COW *);
int copy_ROBIN_NODE_COW(const ROBIN_NODE_COW *, ROBIN_NODE_COW *);


/*
ROBIN-NODE-SYNC ::= [APPLICATION 63] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  disk[3]         RobinDisk OPTIONAL,
  token[4]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_SYNC;

int enc_ROBIN_NODE_SYNC(unsigned char *, size_t, const ROBIN_NODE_SYNC *, size_t *);
int    dec_ROBIN_NODE_SYNC(const unsigned char *, size_t, ROBIN_NODE_SYNC *, size_t *);
void free_ROBIN_NODE_SYNC  (ROBIN_NODE_SYNC *);
size_t len_ROBIN_NODE_SYNC(const ROBIN_NODE_SYNC *);
int copy_ROBIN_NODE_SYNC(const ROBIN_NODE_SYNC *, ROBIN_NODE_SYNC *);


/*
ROBIN-NODE-XFER ::= [APPLICATION 64] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  disk[3]         RobinDisk OPTIONAL,
  token[4]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_XFER;

int enc_ROBIN_NODE_XFER(unsigned char *, size_t, const ROBIN_NODE_XFER *, size_t *);
int    dec_ROBIN_NODE_XFER(const unsigned char *, size_t, ROBIN_NODE_XFER *, size_t *);
void free_ROBIN_NODE_XFER  (ROBIN_NODE_XFER *);
size_t len_ROBIN_NODE_XFER(const ROBIN_NODE_XFER *);
int copy_ROBIN_NODE_XFER(const ROBIN_NODE_XFER *, ROBIN_NODE_XFER *);


/*
ROBIN-NODE-SNAP ::= [APPLICATION 65] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  dhdl[4]         RobinHandle OPTIONAL,
  disk[5]         RobinDisk OPTIONAL,
  token[6]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  RobinHandle *dhdl;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_SNAP;

int enc_ROBIN_NODE_SNAP(unsigned char *, size_t, const ROBIN_NODE_SNAP *, size_t *);
int    dec_ROBIN_NODE_SNAP(const unsigned char *, size_t, ROBIN_NODE_SNAP *, size_t *);
void free_ROBIN_NODE_SNAP  (ROBIN_NODE_SNAP *);
size_t len_ROBIN_NODE_SNAP(const ROBIN_NODE_SNAP *);
int copy_ROBIN_NODE_SNAP(const ROBIN_NODE_SNAP *, ROBIN_NODE_SNAP *);


/*
ROBIN-NODE-GETSUM ::= [APPLICATION 66] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  cksumtype[3]    ROBIN-CKSUMTYPE,
  disk[4]         RobinDisk OPTIONAL,
  token[5]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  ROBIN_CKSUMTYPE cksumtype;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_NODE_GETSUM;

int enc_ROBIN_NODE_GETSUM(unsigned char *, size_t, const ROBIN_NODE_GETSUM *, size_t *);
int    dec_ROBIN_NODE_GETSUM(const unsigned char *, size_t, ROBIN_NODE_GETSUM *, size_t *);
void free_ROBIN_NODE_GETSUM  (ROBIN_NODE_GETSUM *);
size_t len_ROBIN_NODE_GETSUM(const ROBIN_NODE_GETSUM *);
int copy_ROBIN_NODE_GETSUM(const ROBIN_NODE_GETSUM *, ROBIN_NODE_GETSUM *);


/*
ROBIN-LOOKUP ::= [APPLICATION 70] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  name[3]         RobinFilename,
  token[4]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  RobinFilename name;
  RobinToken *token;
} ROBIN_LOOKUP;

int enc_ROBIN_LOOKUP(unsigned char *, size_t, const ROBIN_LOOKUP *, size_t *);
int    dec_ROBIN_LOOKUP(const unsigned char *, size_t, ROBIN_LOOKUP *, size_t *);
void free_ROBIN_LOOKUP  (ROBIN_LOOKUP *);
size_t len_ROBIN_LOOKUP(const ROBIN_LOOKUP *);
int copy_ROBIN_LOOKUP(const ROBIN_LOOKUP *, ROBIN_LOOKUP *);


/*
ROBIN-READDIR ::= [APPLICATION 71] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  hdl[2]          RobinHandle,
  limit[3]        INTEGER OPTIONAL,
  last[4]         RobinDirentry OPTIONAL,
  token[5]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle hdl;
  int32_t *limit;
  RobinDirentry *last;
  RobinToken *token;
} ROBIN_READDIR;

int enc_ROBIN_READDIR(unsigned char *, size_t, const ROBIN_READDIR *, size_t *);
int    dec_ROBIN_READDIR(const unsigned char *, size_t, ROBIN_READDIR *, size_t *);
void free_ROBIN_READDIR  (ROBIN_READDIR *);
size_t len_ROBIN_READDIR(const ROBIN_READDIR *);
int copy_ROBIN_READDIR(const ROBIN_READDIR *, ROBIN_READDIR *);


/*
ROBIN-DIRLINK ::= [APPLICATION 72] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  hdl[4]          RobinHandle,
  name[5]         RobinFilename,
  type[6]         ROBIN-TYPE,
  disk[7]         RobinDisk OPTIONAL,
  token[8]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinHandle hdl;
  RobinFilename name;
  ROBIN_TYPE type;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRLINK;

int enc_ROBIN_DIRLINK(unsigned char *, size_t, const ROBIN_DIRLINK *, size_t *);
int    dec_ROBIN_DIRLINK(const unsigned char *, size_t, ROBIN_DIRLINK *, size_t *);
void free_ROBIN_DIRLINK  (ROBIN_DIRLINK *);
size_t len_ROBIN_DIRLINK(const ROBIN_DIRLINK *);
int copy_ROBIN_DIRLINK(const ROBIN_DIRLINK *, ROBIN_DIRLINK *);


/*
ROBIN-DIRUNLINK ::= [APPLICATION 73] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  hdl[4]          RobinHandle,
  name[5]         RobinFilename,
  disk[6]         RobinDisk OPTIONAL,
  token[7]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinHandle hdl;
  RobinFilename name;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRUNLINK;

int enc_ROBIN_DIRUNLINK(unsigned char *, size_t, const ROBIN_DIRUNLINK *, size_t *);
int    dec_ROBIN_DIRUNLINK(const unsigned char *, size_t, ROBIN_DIRUNLINK *, size_t *);
void free_ROBIN_DIRUNLINK  (ROBIN_DIRUNLINK *);
size_t len_ROBIN_DIRUNLINK(const ROBIN_DIRUNLINK *);
int copy_ROBIN_DIRUNLINK(const ROBIN_DIRUNLINK *, ROBIN_DIRUNLINK *);


/*
ROBIN-DIRRELINK ::= [APPLICATION 74] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  hdl[4]          RobinHandle,
  name[5]         RobinFilename,
  type[6]         ROBIN-TYPE,
  disk[7]         RobinDisk OPTIONAL,
  token[8]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinHandle hdl;
  RobinFilename name;
  ROBIN_TYPE type;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRRELINK;

int enc_ROBIN_DIRRELINK(unsigned char *, size_t, const ROBIN_DIRRELINK *, size_t *);
int    dec_ROBIN_DIRRELINK(const unsigned char *, size_t, ROBIN_DIRRELINK *, size_t *);
void free_ROBIN_DIRRELINK  (ROBIN_DIRRELINK *);
size_t len_ROBIN_DIRRELINK(const ROBIN_DIRRELINK *);
int copy_ROBIN_DIRRELINK(const ROBIN_DIRRELINK *, ROBIN_DIRRELINK *);


/*
ROBIN-DIRCREATE ::= [APPLICATION 75] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  hdl[4]          RobinHandle OPTIONAL,
  name[5]         RobinFilename,
  attr[6]         RobinAttributes,
  sum[7]          RobinChecksum OPTIONAL,
  lock[8]         ROBIN-LOCKTYPE OPTIONAL,
  disk[9]         RobinDisk OPTIONAL,
  token[10]       RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinHandle *hdl;
  RobinFilename name;
  RobinAttributes attr;
  RobinChecksum *sum;
  ROBIN_LOCKTYPE *lock;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRCREATE;

int enc_ROBIN_DIRCREATE(unsigned char *, size_t, const ROBIN_DIRCREATE *, size_t *);
int    dec_ROBIN_DIRCREATE(const unsigned char *, size_t, ROBIN_DIRCREATE *, size_t *);
void free_ROBIN_DIRCREATE  (ROBIN_DIRCREATE *);
size_t len_ROBIN_DIRCREATE(const ROBIN_DIRCREATE *);
int copy_ROBIN_DIRCREATE(const ROBIN_DIRCREATE *, ROBIN_DIRCREATE *);


/*
ROBIN-DIRSYMLINK ::= [APPLICATION 76] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  hdl[4]          RobinHandle OPTIONAL,
  name[5]         RobinFilename,
  attr[6]         RobinAttributes,
  dest[7]         RobinFilename,
  lock[8]         ROBIN-LOCKTYPE OPTIONAL,
  disk[9]         RobinDisk OPTIONAL,
  token[10]       RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinHandle *hdl;
  RobinFilename name;
  RobinAttributes attr;
  RobinFilename dest;
  ROBIN_LOCKTYPE *lock;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRSYMLINK;

int enc_ROBIN_DIRSYMLINK(unsigned char *, size_t, const ROBIN_DIRSYMLINK *, size_t *);
int    dec_ROBIN_DIRSYMLINK(const unsigned char *, size_t, ROBIN_DIRSYMLINK *, size_t *);
void free_ROBIN_DIRSYMLINK  (ROBIN_DIRSYMLINK *);
size_t len_ROBIN_DIRSYMLINK(const ROBIN_DIRSYMLINK *);
int copy_ROBIN_DIRSYMLINK(const ROBIN_DIRSYMLINK *, ROBIN_DIRSYMLINK *);


/*
ROBIN-DIRRENAME ::= [APPLICATION 77] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  oldphdl[4]      RobinHandle,
  oldname[5]      RobinFilename,
  newphdl[6]      RobinHandle,
  newname[7]      RobinFilename,
  type[8]         ROBIN-TYPE,
  disk[9]         RobinDisk OPTIONAL,
  token[10]       RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  RobinHandle oldphdl;
  RobinFilename oldname;
  RobinHandle newphdl;
  RobinFilename newname;
  ROBIN_TYPE type;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRRENAME;

int enc_ROBIN_DIRRENAME(unsigned char *, size_t, const ROBIN_DIRRENAME *, size_t *);
int    dec_ROBIN_DIRRENAME(const unsigned char *, size_t, ROBIN_DIRRENAME *, size_t *);
void free_ROBIN_DIRRENAME  (ROBIN_DIRRENAME *);
size_t len_ROBIN_DIRRENAME(const ROBIN_DIRRENAME *);
int copy_ROBIN_DIRRENAME(const ROBIN_DIRRENAME *, ROBIN_DIRRENAME *);


/*
ROBIN-DIRHISTGET ::= [APPLICATION 78] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  name[4]         RobinFilename,
  last[5]         INTEGER,
  limit[6]        INTEGER,
  disk[7]         RobinDisk OPTIONAL,
  token[8]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinFilename name;
  int32_t last;
  int32_t limit;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRHISTGET;

int enc_ROBIN_DIRHISTGET(unsigned char *, size_t, const ROBIN_DIRHISTGET *, size_t *);
int    dec_ROBIN_DIRHISTGET(const unsigned char *, size_t, ROBIN_DIRHISTGET *, size_t *);
void free_ROBIN_DIRHISTGET  (ROBIN_DIRHISTGET *);
size_t len_ROBIN_DIRHISTGET(const ROBIN_DIRHISTGET *);
int copy_ROBIN_DIRHISTGET(const ROBIN_DIRHISTGET *, ROBIN_DIRHISTGET *);


/*
ROBIN-DIRHISTSET ::= [APPLICATION 79] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  phdl[3]         RobinHandle,
  name[4]         RobinFilename OPTIONAL,
  limit[5]        INTEGER,
  disk[6]         RobinDisk OPTIONAL,
  token[7]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle *vhdl;
  RobinHandle phdl;
  RobinFilename *name;
  int32_t limit;
  RobinDisk *disk;
  RobinToken *token;
} ROBIN_DIRHISTSET;

int enc_ROBIN_DIRHISTSET(unsigned char *, size_t, const ROBIN_DIRHISTSET *, size_t *);
int    dec_ROBIN_DIRHISTSET(const unsigned char *, size_t, ROBIN_DIRHISTSET *, size_t *);
void free_ROBIN_DIRHISTSET  (ROBIN_DIRHISTSET *);
size_t len_ROBIN_DIRHISTSET(const ROBIN_DIRHISTSET *);
int copy_ROBIN_DIRHISTSET(const ROBIN_DIRHISTSET *, ROBIN_DIRHISTSET *);


/*
ROBIN-GROUP-CREATE ::= [APPLICATION 80] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal,
  owner[2]        RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
  RobinPrincipal owner;
} ROBIN_GROUP_CREATE;

int enc_ROBIN_GROUP_CREATE(unsigned char *, size_t, const ROBIN_GROUP_CREATE *, size_t *);
int    dec_ROBIN_GROUP_CREATE(const unsigned char *, size_t, ROBIN_GROUP_CREATE *, size_t *);
void free_ROBIN_GROUP_CREATE  (ROBIN_GROUP_CREATE *);
size_t len_ROBIN_GROUP_CREATE(const ROBIN_GROUP_CREATE *);
int copy_ROBIN_GROUP_CREATE(const ROBIN_GROUP_CREATE *, ROBIN_GROUP_CREATE *);


/*
ROBIN-GROUP-DELETE ::= [APPLICATION 81] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
} ROBIN_GROUP_DELETE;

int enc_ROBIN_GROUP_DELETE(unsigned char *, size_t, const ROBIN_GROUP_DELETE *, size_t *);
int    dec_ROBIN_GROUP_DELETE(const unsigned char *, size_t, ROBIN_GROUP_DELETE *, size_t *);
void free_ROBIN_GROUP_DELETE  (ROBIN_GROUP_DELETE *);
size_t len_ROBIN_GROUP_DELETE(const ROBIN_GROUP_DELETE *);
int copy_ROBIN_GROUP_DELETE(const ROBIN_GROUP_DELETE *, ROBIN_GROUP_DELETE *);


/*
ROBIN-GROUP-MODIFY ::= [APPLICATION 82] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal,
  owner[2]        RobinPrincipal OPTIONAL,
  public[3]       RobinGroupRight OPTIONAL,
  private[4]      RobinGroupRight OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
  RobinPrincipal *owner;
  RobinGroupRight *public;
  RobinGroupRight *private;
} ROBIN_GROUP_MODIFY;

int enc_ROBIN_GROUP_MODIFY(unsigned char *, size_t, const ROBIN_GROUP_MODIFY *, size_t *);
int    dec_ROBIN_GROUP_MODIFY(const unsigned char *, size_t, ROBIN_GROUP_MODIFY *, size_t *);
void free_ROBIN_GROUP_MODIFY  (ROBIN_GROUP_MODIFY *);
size_t len_ROBIN_GROUP_MODIFY(const ROBIN_GROUP_MODIFY *);
int copy_ROBIN_GROUP_MODIFY(const ROBIN_GROUP_MODIFY *, ROBIN_GROUP_MODIFY *);


/*
ROBIN-GROUP-RENAME ::= [APPLICATION 83] SEQUENCE {
  hdr[0]          RobinHeader,
  old_group[1]    RobinPrincipal,
  new_group[2]    RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal old_group;
  RobinPrincipal new_group;
} ROBIN_GROUP_RENAME;

int enc_ROBIN_GROUP_RENAME(unsigned char *, size_t, const ROBIN_GROUP_RENAME *, size_t *);
int    dec_ROBIN_GROUP_RENAME(const unsigned char *, size_t, ROBIN_GROUP_RENAME *, size_t *);
void free_ROBIN_GROUP_RENAME  (ROBIN_GROUP_RENAME *);
size_t len_ROBIN_GROUP_RENAME(const ROBIN_GROUP_RENAME *);
int copy_ROBIN_GROUP_RENAME(const ROBIN_GROUP_RENAME *, ROBIN_GROUP_RENAME *);


/*
ROBIN-GROUP-ADD ::= [APPLICATION 84] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal,
  user[2]         RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
  RobinPrincipal user;
} ROBIN_GROUP_ADD;

int enc_ROBIN_GROUP_ADD(unsigned char *, size_t, const ROBIN_GROUP_ADD *, size_t *);
int    dec_ROBIN_GROUP_ADD(const unsigned char *, size_t, ROBIN_GROUP_ADD *, size_t *);
void free_ROBIN_GROUP_ADD  (ROBIN_GROUP_ADD *);
size_t len_ROBIN_GROUP_ADD(const ROBIN_GROUP_ADD *);
int copy_ROBIN_GROUP_ADD(const ROBIN_GROUP_ADD *, ROBIN_GROUP_ADD *);


/*
ROBIN-GROUP-DEL ::= [APPLICATION 85] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal,
  user[2]         RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
  RobinPrincipal user;
} ROBIN_GROUP_DEL;

int enc_ROBIN_GROUP_DEL(unsigned char *, size_t, const ROBIN_GROUP_DEL *, size_t *);
int    dec_ROBIN_GROUP_DEL(const unsigned char *, size_t, ROBIN_GROUP_DEL *, size_t *);
void free_ROBIN_GROUP_DEL  (ROBIN_GROUP_DEL *);
size_t len_ROBIN_GROUP_DEL(const ROBIN_GROUP_DEL *);
int copy_ROBIN_GROUP_DEL(const ROBIN_GROUP_DEL *, ROBIN_GROUP_DEL *);


/*
ROBIN-GROUP-GET ::= [APPLICATION 86] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
} ROBIN_GROUP_GET;

int enc_ROBIN_GROUP_GET(unsigned char *, size_t, const ROBIN_GROUP_GET *, size_t *);
int    dec_ROBIN_GROUP_GET(const unsigned char *, size_t, ROBIN_GROUP_GET *, size_t *);
void free_ROBIN_GROUP_GET  (ROBIN_GROUP_GET *);
size_t len_ROBIN_GROUP_GET(const ROBIN_GROUP_GET *);
int copy_ROBIN_GROUP_GET(const ROBIN_GROUP_GET *, ROBIN_GROUP_GET *);


/*
ROBIN-GROUP-PUT ::= [APPLICATION 87] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal,
  users[2]        RobinPrincipals
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
  RobinPrincipals users;
} ROBIN_GROUP_PUT;

int enc_ROBIN_GROUP_PUT(unsigned char *, size_t, const ROBIN_GROUP_PUT *, size_t *);
int    dec_ROBIN_GROUP_PUT(const unsigned char *, size_t, ROBIN_GROUP_PUT *, size_t *);
void free_ROBIN_GROUP_PUT  (ROBIN_GROUP_PUT *);
size_t len_ROBIN_GROUP_PUT(const ROBIN_GROUP_PUT *);
int copy_ROBIN_GROUP_PUT(const ROBIN_GROUP_PUT *, ROBIN_GROUP_PUT *);


/*
ROBIN-GROUP-EVAL ::= [APPLICATION 88] SEQUENCE {
  hdr[0]          RobinHeader,
  group[1]        RobinPrincipal,
  user[2]         RobinPrincipal
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinPrincipal group;
  RobinPrincipal user;
} ROBIN_GROUP_EVAL;

int enc_ROBIN_GROUP_EVAL(unsigned char *, size_t, const ROBIN_GROUP_EVAL *, size_t *);
int    dec_ROBIN_GROUP_EVAL(const unsigned char *, size_t, ROBIN_GROUP_EVAL *, size_t *);
void free_ROBIN_GROUP_EVAL  (ROBIN_GROUP_EVAL *);
size_t len_ROBIN_GROUP_EVAL(const ROBIN_GROUP_EVAL *);
int copy_ROBIN_GROUP_EVAL(const ROBIN_GROUP_EVAL *, ROBIN_GROUP_EVAL *);


/*
ROBIN-IHAVE-PART ::= [APPLICATION 90] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags,
  diskflags[2]    RobinDiskFlags,
  partition[3]    RobinPartition,
  partspace[4]    INTEGER64,
  usedspace[5]    INTEGER64,
  freespace[6]    INTEGER64,
  partnodes[7]    INTEGER64,
  usednodes[8]    INTEGER64,
  freenodes[9]    INTEGER64,
  neednodes[10]   INTEGER64,
  maxblock[11]    INTEGER64,
  lastmount[12]   RobinTime,
  totperf[13]     RobinDiskStats OPTIONAL,
  curperf[14]     RobinDiskStats OPTIONAL,
  tokenkey[15]    RobinEncryptionKey OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
  RobinDiskFlags diskflags;
  RobinPartition partition;
  int64_t partspace;
  int64_t usedspace;
  int64_t freespace;
  int64_t partnodes;
  int64_t usednodes;
  int64_t freenodes;
  int64_t neednodes;
  int64_t maxblock;
  RobinTime lastmount;
  RobinDiskStats *totperf;
  RobinDiskStats *curperf;
  RobinEncryptionKey *tokenkey;
} ROBIN_IHAVE_PART;

int enc_ROBIN_IHAVE_PART(unsigned char *, size_t, const ROBIN_IHAVE_PART *, size_t *);
int    dec_ROBIN_IHAVE_PART(const unsigned char *, size_t, ROBIN_IHAVE_PART *, size_t *);
void free_ROBIN_IHAVE_PART  (ROBIN_IHAVE_PART *);
size_t len_ROBIN_IHAVE_PART(const ROBIN_IHAVE_PART *);
int copy_ROBIN_IHAVE_PART(const ROBIN_IHAVE_PART *, ROBIN_IHAVE_PART *);


/*
ROBIN-IHAVE-VOLUME ::= [APPLICATION 91] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags,
  vhdl[2]         RobinHandle,
  attr[3]         RobinAttributes,
  sum[4]          RobinChecksum OPTIONAL,
  token[5]        RobinToken OPTIONAL,
  selfname[6]     RobinFilename OPTIONAL,
  roothdl[7]      RobinHandle,
  atime[8]        RobinTime,
  mtime[9]        RobinTime,
  realsize[10]    INTEGER64 OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
  RobinHandle vhdl;
  RobinAttributes attr;
  RobinChecksum *sum;
  RobinToken *token;
  RobinFilename *selfname;
  RobinHandle roothdl;
  RobinTime atime;
  RobinTime mtime;
  int64_t *realsize;
} ROBIN_IHAVE_VOLUME;

int enc_ROBIN_IHAVE_VOLUME(unsigned char *, size_t, const ROBIN_IHAVE_VOLUME *, size_t *);
int    dec_ROBIN_IHAVE_VOLUME(const unsigned char *, size_t, ROBIN_IHAVE_VOLUME *, size_t *);
void free_ROBIN_IHAVE_VOLUME  (ROBIN_IHAVE_VOLUME *);
size_t len_ROBIN_IHAVE_VOLUME(const ROBIN_IHAVE_VOLUME *);
int copy_ROBIN_IHAVE_VOLUME(const ROBIN_IHAVE_VOLUME *, ROBIN_IHAVE_VOLUME *);


/*
ROBIN-IHAVE-NODE ::= [APPLICATION 92] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  type[4]         ROBIN-TYPE,
  size[5]         INTEGER64,
  sum[6]          RobinChecksum,
  token[7]        RobinToken OPTIONAL,
  atime[8]        RobinTime,
  mtime[9]        RobinTime,
  muser[10]       RobinPrincipal OPTIONAL,
  realsize[11]    INTEGER64 OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  ROBIN_TYPE type;
  int64_t size;
  RobinChecksum sum;
  RobinToken *token;
  RobinTime atime;
  RobinTime mtime;
  RobinPrincipal *muser;
  int64_t *realsize;
} ROBIN_IHAVE_NODE;

int enc_ROBIN_IHAVE_NODE(unsigned char *, size_t, const ROBIN_IHAVE_NODE *, size_t *);
int    dec_ROBIN_IHAVE_NODE(const unsigned char *, size_t, ROBIN_IHAVE_NODE *, size_t *);
void free_ROBIN_IHAVE_NODE  (ROBIN_IHAVE_NODE *);
size_t len_ROBIN_IHAVE_NODE(const ROBIN_IHAVE_NODE *);
int copy_ROBIN_IHAVE_NODE(const ROBIN_IHAVE_NODE *, ROBIN_IHAVE_NODE *);


/*
ROBIN-IHAVE-ROUTE ::= [APPLICATION 93] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags,
  hdl[2]          RobinHandle,
  prefix[3]       INTEGER,
  rtype[4]        INTEGER,
  ttl[5]          INTEGER
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
  RobinHandle hdl;
  int32_t prefix;
  int32_t rtype;
  int32_t ttl;
} ROBIN_IHAVE_ROUTE;

int enc_ROBIN_IHAVE_ROUTE(unsigned char *, size_t, const ROBIN_IHAVE_ROUTE *, size_t *);
int    dec_ROBIN_IHAVE_ROUTE(const unsigned char *, size_t, ROBIN_IHAVE_ROUTE *, size_t *);
void free_ROBIN_IHAVE_ROUTE  (ROBIN_IHAVE_ROUTE *);
size_t len_ROBIN_IHAVE_ROUTE(const ROBIN_IHAVE_ROUTE *);
int copy_ROBIN_IHAVE_ROUTE(const ROBIN_IHAVE_ROUTE *, ROBIN_IHAVE_ROUTE *);


/*
ROBIN-IHAVE-FINISHED ::= [APPLICATION 94] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
} ROBIN_IHAVE_FINISHED;

int enc_ROBIN_IHAVE_FINISHED(unsigned char *, size_t, const ROBIN_IHAVE_FINISHED *, size_t *);
int    dec_ROBIN_IHAVE_FINISHED(const unsigned char *, size_t, ROBIN_IHAVE_FINISHED *, size_t *);
void free_ROBIN_IHAVE_FINISHED  (ROBIN_IHAVE_FINISHED *);
size_t len_ROBIN_IHAVE_FINISHED(const ROBIN_IHAVE_FINISHED *);
int copy_ROBIN_IHAVE_FINISHED(const ROBIN_IHAVE_FINISHED *, ROBIN_IHAVE_FINISHED *);


/*
ROBIN-IHAVE-GROUP ::= [APPLICATION 95] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinGroupFlags
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinGroupFlags flags;
} ROBIN_IHAVE_GROUP;

int enc_ROBIN_IHAVE_GROUP(unsigned char *, size_t, const ROBIN_IHAVE_GROUP *, size_t *);
int    dec_ROBIN_IHAVE_GROUP(const unsigned char *, size_t, ROBIN_IHAVE_GROUP *, size_t *);
void free_ROBIN_IHAVE_GROUP  (ROBIN_IHAVE_GROUP *);
size_t len_ROBIN_IHAVE_GROUP(const ROBIN_IHAVE_GROUP *);
int copy_ROBIN_IHAVE_GROUP(const ROBIN_IHAVE_GROUP *, ROBIN_IHAVE_GROUP *);


/*
ROBIN-IHAVE-TRANS ::= [APPLICATION 96] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinTransFlags,
  token[2]        RobinToken,
  offset[3]       INTEGER64,
  length[4]       INTEGER64,
  append[5]       INTEGER64,
  txid[6]         OCTET STRING
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinTransFlags flags;
  RobinToken token;
  int64_t offset;
  int64_t length;
  int64_t append;
  tb_octet_string txid;
} ROBIN_IHAVE_TRANS;

int enc_ROBIN_IHAVE_TRANS(unsigned char *, size_t, const ROBIN_IHAVE_TRANS *, size_t *);
int    dec_ROBIN_IHAVE_TRANS(const unsigned char *, size_t, ROBIN_IHAVE_TRANS *, size_t *);
void free_ROBIN_IHAVE_TRANS  (ROBIN_IHAVE_TRANS *);
size_t len_ROBIN_IHAVE_TRANS(const ROBIN_IHAVE_TRANS *);
int copy_ROBIN_IHAVE_TRANS(const ROBIN_IHAVE_TRANS *, ROBIN_IHAVE_TRANS *);


/*
ROBIN-IHAVE-WITHDRAW ::= [APPLICATION 97] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags,
  vhdl[2]         RobinHandle OPTIONAL,
  hdl[3]          RobinHandle,
  type[4]         ROBIN-TYPE,
  errorcode[5]    INTEGER
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
  RobinHandle *vhdl;
  RobinHandle hdl;
  ROBIN_TYPE type;
  int32_t errorcode;
} ROBIN_IHAVE_WITHDRAW;

int enc_ROBIN_IHAVE_WITHDRAW(unsigned char *, size_t, const ROBIN_IHAVE_WITHDRAW *, size_t *);
int    dec_ROBIN_IHAVE_WITHDRAW(const unsigned char *, size_t, ROBIN_IHAVE_WITHDRAW *, size_t *);
void free_ROBIN_IHAVE_WITHDRAW  (ROBIN_IHAVE_WITHDRAW *);
size_t len_ROBIN_IHAVE_WITHDRAW(const ROBIN_IHAVE_WITHDRAW *);
int copy_ROBIN_IHAVE_WITHDRAW(const ROBIN_IHAVE_WITHDRAW *, ROBIN_IHAVE_WITHDRAW *);


/*
ROBIN-IHAVE-PROTECT ::= [APPLICATION 98] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinRouterFlags,
  rules[2]        RobinProtectNodes
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinRouterFlags flags;
  RobinProtectNodes rules;
} ROBIN_IHAVE_PROTECT;

int enc_ROBIN_IHAVE_PROTECT(unsigned char *, size_t, const ROBIN_IHAVE_PROTECT *, size_t *);
int    dec_ROBIN_IHAVE_PROTECT(const unsigned char *, size_t, ROBIN_IHAVE_PROTECT *, size_t *);
void free_ROBIN_IHAVE_PROTECT  (ROBIN_IHAVE_PROTECT *);
size_t len_ROBIN_IHAVE_PROTECT(const ROBIN_IHAVE_PROTECT *);
int copy_ROBIN_IHAVE_PROTECT(const ROBIN_IHAVE_PROTECT *, ROBIN_IHAVE_PROTECT *);


/*
ROBIN-VOLUME-GETROOT ::= [APPLICATION 100] SEQUENCE {
  hdr[0]          RobinHeader,
  flags[1]        RobinNodeFlags,
  vhdl[2]         RobinHandle
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinNodeFlags flags;
  RobinHandle vhdl;
} ROBIN_VOLUME_GETROOT;

int enc_ROBIN_VOLUME_GETROOT(unsigned char *, size_t, const ROBIN_VOLUME_GETROOT *, size_t *);
int    dec_ROBIN_VOLUME_GETROOT(const unsigned char *, size_t, ROBIN_VOLUME_GETROOT *, size_t *);
void free_ROBIN_VOLUME_GETROOT  (ROBIN_VOLUME_GETROOT *);
size_t len_ROBIN_VOLUME_GETROOT(const ROBIN_VOLUME_GETROOT *);
int copy_ROBIN_VOLUME_GETROOT(const ROBIN_VOLUME_GETROOT *, ROBIN_VOLUME_GETROOT *);


/*
ROBIN-VOLUME-SETROOT ::= [APPLICATION 101] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
} ROBIN_VOLUME_SETROOT;

int enc_ROBIN_VOLUME_SETROOT(unsigned char *, size_t, const ROBIN_VOLUME_SETROOT *, size_t *);
int    dec_ROBIN_VOLUME_SETROOT(const unsigned char *, size_t, ROBIN_VOLUME_SETROOT *, size_t *);
void free_ROBIN_VOLUME_SETROOT  (ROBIN_VOLUME_SETROOT *);
size_t len_ROBIN_VOLUME_SETROOT(const ROBIN_VOLUME_SETROOT *);
int copy_ROBIN_VOLUME_SETROOT(const ROBIN_VOLUME_SETROOT *, ROBIN_VOLUME_SETROOT *);


/*
ROBIN-VOLUME-CREATE ::= [APPLICATION 102] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  attr[2]         RobinAttributes,
  quota[3]        RobinQuota,
  name[4]         RobinFilename OPTIONAL,
  token[5]        RobinToken OPTIONAL,
  rules[6]        RobinProtectNodes OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinAttributes attr;
  RobinQuota quota;
  RobinFilename *name;
  RobinToken *token;
  RobinProtectNodes *rules;
} ROBIN_VOLUME_CREATE;

int enc_ROBIN_VOLUME_CREATE(unsigned char *, size_t, const ROBIN_VOLUME_CREATE *, size_t *);
int    dec_ROBIN_VOLUME_CREATE(const unsigned char *, size_t, ROBIN_VOLUME_CREATE *, size_t *);
void free_ROBIN_VOLUME_CREATE  (ROBIN_VOLUME_CREATE *);
size_t len_ROBIN_VOLUME_CREATE(const ROBIN_VOLUME_CREATE *);
int copy_ROBIN_VOLUME_CREATE(const ROBIN_VOLUME_CREATE *, ROBIN_VOLUME_CREATE *);


/*
ROBIN-VOLUME-MKNODE ::= [APPLICATION 103] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle OPTIONAL,
  attr[3]         RobinAttributes,
  sum[4]          RobinChecksum OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle *hdl;
  RobinAttributes attr;
  RobinChecksum *sum;
} ROBIN_VOLUME_MKNODE;

int enc_ROBIN_VOLUME_MKNODE(unsigned char *, size_t, const ROBIN_VOLUME_MKNODE *, size_t *);
int    dec_ROBIN_VOLUME_MKNODE(const unsigned char *, size_t, ROBIN_VOLUME_MKNODE *, size_t *);
void free_ROBIN_VOLUME_MKNODE  (ROBIN_VOLUME_MKNODE *);
size_t len_ROBIN_VOLUME_MKNODE(const ROBIN_VOLUME_MKNODE *);
int copy_ROBIN_VOLUME_MKNODE(const ROBIN_VOLUME_MKNODE *, ROBIN_VOLUME_MKNODE *);


/*
ROBIN-VOLUME-CHNODE ::= [APPLICATION 104] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle,
  attr[3]         RobinAttributes,
  sum[4]          RobinChecksum OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
  RobinAttributes attr;
  RobinChecksum *sum;
} ROBIN_VOLUME_CHNODE;

int enc_ROBIN_VOLUME_CHNODE(unsigned char *, size_t, const ROBIN_VOLUME_CHNODE *, size_t *);
int    dec_ROBIN_VOLUME_CHNODE(const unsigned char *, size_t, ROBIN_VOLUME_CHNODE *, size_t *);
void free_ROBIN_VOLUME_CHNODE  (ROBIN_VOLUME_CHNODE *);
size_t len_ROBIN_VOLUME_CHNODE(const ROBIN_VOLUME_CHNODE *);
int copy_ROBIN_VOLUME_CHNODE(const ROBIN_VOLUME_CHNODE *, ROBIN_VOLUME_CHNODE *);


/*
ROBIN-VOLUME-STNODE ::= [APPLICATION 105] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
} ROBIN_VOLUME_STNODE;

int enc_ROBIN_VOLUME_STNODE(unsigned char *, size_t, const ROBIN_VOLUME_STNODE *, size_t *);
int    dec_ROBIN_VOLUME_STNODE(const unsigned char *, size_t, ROBIN_VOLUME_STNODE *, size_t *);
void free_ROBIN_VOLUME_STNODE  (ROBIN_VOLUME_STNODE *);
size_t len_ROBIN_VOLUME_STNODE(const ROBIN_VOLUME_STNODE *);
int copy_ROBIN_VOLUME_STNODE(const ROBIN_VOLUME_STNODE *, ROBIN_VOLUME_STNODE *);


/*
ROBIN-VOLUME-RMNODE ::= [APPLICATION 106] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
} ROBIN_VOLUME_RMNODE;

int enc_ROBIN_VOLUME_RMNODE(unsigned char *, size_t, const ROBIN_VOLUME_RMNODE *, size_t *);
int    dec_ROBIN_VOLUME_RMNODE(const unsigned char *, size_t, ROBIN_VOLUME_RMNODE *, size_t *);
void free_ROBIN_VOLUME_RMNODE  (ROBIN_VOLUME_RMNODE *);
size_t len_ROBIN_VOLUME_RMNODE(const ROBIN_VOLUME_RMNODE *);
int copy_ROBIN_VOLUME_RMNODE(const ROBIN_VOLUME_RMNODE *, ROBIN_VOLUME_RMNODE *);


/*
ROBIN-VOLUME-SNAPSHOT ::= [APPLICATION 107] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  dhdl[2]         RobinHandle OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle *dhdl;
} ROBIN_VOLUME_SNAPSHOT;

int enc_ROBIN_VOLUME_SNAPSHOT(unsigned char *, size_t, const ROBIN_VOLUME_SNAPSHOT *, size_t *);
int    dec_ROBIN_VOLUME_SNAPSHOT(const unsigned char *, size_t, ROBIN_VOLUME_SNAPSHOT *, size_t *);
void free_ROBIN_VOLUME_SNAPSHOT  (ROBIN_VOLUME_SNAPSHOT *);
size_t len_ROBIN_VOLUME_SNAPSHOT(const ROBIN_VOLUME_SNAPSHOT *);
int copy_ROBIN_VOLUME_SNAPSHOT(const ROBIN_VOLUME_SNAPSHOT *, ROBIN_VOLUME_SNAPSHOT *);


/*
ROBIN-VOLUME-DIRLINK ::= [APPLICATION 108] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  phdl[2]         RobinHandle,
  hdl[3]          RobinHandle,
  name[4]         RobinFilename,
  token[5]        RobinToken
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle phdl;
  RobinHandle hdl;
  RobinFilename name;
  RobinToken token;
} ROBIN_VOLUME_DIRLINK;

int enc_ROBIN_VOLUME_DIRLINK(unsigned char *, size_t, const ROBIN_VOLUME_DIRLINK *, size_t *);
int    dec_ROBIN_VOLUME_DIRLINK(const unsigned char *, size_t, ROBIN_VOLUME_DIRLINK *, size_t *);
void free_ROBIN_VOLUME_DIRLINK  (ROBIN_VOLUME_DIRLINK *);
size_t len_ROBIN_VOLUME_DIRLINK(const ROBIN_VOLUME_DIRLINK *);
int copy_ROBIN_VOLUME_DIRLINK(const ROBIN_VOLUME_DIRLINK *, ROBIN_VOLUME_DIRLINK *);


/*
ROBIN-VOLUME-DIRUNLINK ::= [APPLICATION 109] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  phdl[2]         RobinHandle,
  hdl[3]          RobinHandle,
  name[4]         RobinFilename,
  token[5]        RobinToken
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle phdl;
  RobinHandle hdl;
  RobinFilename name;
  RobinToken token;
} ROBIN_VOLUME_DIRUNLINK;

int enc_ROBIN_VOLUME_DIRUNLINK(unsigned char *, size_t, const ROBIN_VOLUME_DIRUNLINK *, size_t *);
int    dec_ROBIN_VOLUME_DIRUNLINK(const unsigned char *, size_t, ROBIN_VOLUME_DIRUNLINK *, size_t *);
void free_ROBIN_VOLUME_DIRUNLINK  (ROBIN_VOLUME_DIRUNLINK *);
size_t len_ROBIN_VOLUME_DIRUNLINK(const ROBIN_VOLUME_DIRUNLINK *);
int copy_ROBIN_VOLUME_DIRUNLINK(const ROBIN_VOLUME_DIRUNLINK *, ROBIN_VOLUME_DIRUNLINK *);


/*
ROBIN-VOLUME-VRNODE ::= [APPLICATION 110] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle,
  token[3]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
  RobinToken *token;
} ROBIN_VOLUME_VRNODE;

int enc_ROBIN_VOLUME_VRNODE(unsigned char *, size_t, const ROBIN_VOLUME_VRNODE *, size_t *);
int    dec_ROBIN_VOLUME_VRNODE(const unsigned char *, size_t, ROBIN_VOLUME_VRNODE *, size_t *);
void free_ROBIN_VOLUME_VRNODE  (ROBIN_VOLUME_VRNODE *);
size_t len_ROBIN_VOLUME_VRNODE(const ROBIN_VOLUME_VRNODE *);
int copy_ROBIN_VOLUME_VRNODE(const ROBIN_VOLUME_VRNODE *, ROBIN_VOLUME_VRNODE *);


/*
ROBIN-VOLUME-VRSIZE ::= [APPLICATION 111] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle,
  size[3]         INTEGER64,
  token[4]        RobinToken OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
  int64_t size;
  RobinToken *token;
} ROBIN_VOLUME_VRSIZE;

int enc_ROBIN_VOLUME_VRSIZE(unsigned char *, size_t, const ROBIN_VOLUME_VRSIZE *, size_t *);
int    dec_ROBIN_VOLUME_VRSIZE(const unsigned char *, size_t, ROBIN_VOLUME_VRSIZE *, size_t *);
void free_ROBIN_VOLUME_VRSIZE  (ROBIN_VOLUME_VRSIZE *);
size_t len_ROBIN_VOLUME_VRSIZE(const ROBIN_VOLUME_VRSIZE *);
int copy_ROBIN_VOLUME_VRSIZE(const ROBIN_VOLUME_VRSIZE *, ROBIN_VOLUME_VRSIZE *);


/*
ROBIN-VOLUME-RACL ::= [APPLICATION 112] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle,
  principal[3]    RobinPrincipal OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
  RobinPrincipal *principal;
} ROBIN_VOLUME_RACL;

int enc_ROBIN_VOLUME_RACL(unsigned char *, size_t, const ROBIN_VOLUME_RACL *, size_t *);
int    dec_ROBIN_VOLUME_RACL(const unsigned char *, size_t, ROBIN_VOLUME_RACL *, size_t *);
void free_ROBIN_VOLUME_RACL  (ROBIN_VOLUME_RACL *);
size_t len_ROBIN_VOLUME_RACL(const ROBIN_VOLUME_RACL *);
int copy_ROBIN_VOLUME_RACL(const ROBIN_VOLUME_RACL *, ROBIN_VOLUME_RACL *);


/*
ROBIN-VOLUME-WACL ::= [APPLICATION 113] SEQUENCE {
  hdr[0]          RobinHeader,
  vhdl[1]         RobinHandle,
  hdl[2]          RobinHandle,
  append[3]       RobinRightsList OPTIONAL,
  change[4]       RobinRightsList OPTIONAL,
  delete[5]       RobinRightsList OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle vhdl;
  RobinHandle hdl;
  RobinRightsList *append;
  RobinRightsList *change;
  RobinRightsList *delete;
} ROBIN_VOLUME_WACL;

int enc_ROBIN_VOLUME_WACL(unsigned char *, size_t, const ROBIN_VOLUME_WACL *, size_t *);
int    dec_ROBIN_VOLUME_WACL(const unsigned char *, size_t, ROBIN_VOLUME_WACL *, size_t *);
void free_ROBIN_VOLUME_WACL  (ROBIN_VOLUME_WACL *);
size_t len_ROBIN_VOLUME_WACL(const ROBIN_VOLUME_WACL *);
int copy_ROBIN_VOLUME_WACL(const ROBIN_VOLUME_WACL *, ROBIN_VOLUME_WACL *);


/*
ROBIN-TOKEN-VERIFY ::= [APPLICATION 120] SEQUENCE {
  hdr[0]          RobinHeader,
  token[1]        RobinToken
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinToken token;
} ROBIN_TOKEN_VERIFY;

int enc_ROBIN_TOKEN_VERIFY(unsigned char *, size_t, const ROBIN_TOKEN_VERIFY *, size_t *);
int    dec_ROBIN_TOKEN_VERIFY(const unsigned char *, size_t, ROBIN_TOKEN_VERIFY *, size_t *);
void free_ROBIN_TOKEN_VERIFY  (ROBIN_TOKEN_VERIFY *);
size_t len_ROBIN_TOKEN_VERIFY(const ROBIN_TOKEN_VERIFY *);
int copy_ROBIN_TOKEN_VERIFY(const ROBIN_TOKEN_VERIFY *, ROBIN_TOKEN_VERIFY *);


/*
ROBIN-TOKEN-PUT ::= [APPLICATION 121] SEQUENCE {
  hdr[0]          RobinHeader,
  token[1]        RobinToken,
  disk[2]         RobinDisk OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinToken token;
  RobinDisk *disk;
} ROBIN_TOKEN_PUT;

int enc_ROBIN_TOKEN_PUT(unsigned char *, size_t, const ROBIN_TOKEN_PUT *, size_t *);
int    dec_ROBIN_TOKEN_PUT(const unsigned char *, size_t, ROBIN_TOKEN_PUT *, size_t *);
void free_ROBIN_TOKEN_PUT  (ROBIN_TOKEN_PUT *);
size_t len_ROBIN_TOKEN_PUT(const ROBIN_TOKEN_PUT *);
int copy_ROBIN_TOKEN_PUT(const ROBIN_TOKEN_PUT *, ROBIN_TOKEN_PUT *);


/*
ROBIN-TOKEN-GET ::= [APPLICATION 122] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  disk[2]         RobinDisk OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  RobinDisk *disk;
} ROBIN_TOKEN_GET;

int enc_ROBIN_TOKEN_GET(unsigned char *, size_t, const ROBIN_TOKEN_GET *, size_t *);
int    dec_ROBIN_TOKEN_GET(const unsigned char *, size_t, ROBIN_TOKEN_GET *, size_t *);
void free_ROBIN_TOKEN_GET  (ROBIN_TOKEN_GET *);
size_t len_ROBIN_TOKEN_GET(const ROBIN_TOKEN_GET *);
int copy_ROBIN_TOKEN_GET(const ROBIN_TOKEN_GET *, ROBIN_TOKEN_GET *);


/*
ROBIN-TOKEN-DEL ::= [APPLICATION 123] SEQUENCE {
  hdr[0]          RobinHeader,
  hdl[1]          RobinHandle,
  disk[2]         RobinDisk OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinHandle hdl;
  RobinDisk *disk;
} ROBIN_TOKEN_DEL;

int enc_ROBIN_TOKEN_DEL(unsigned char *, size_t, const ROBIN_TOKEN_DEL *, size_t *);
int    dec_ROBIN_TOKEN_DEL(const unsigned char *, size_t, ROBIN_TOKEN_DEL *, size_t *);
void free_ROBIN_TOKEN_DEL  (ROBIN_TOKEN_DEL *);
size_t len_ROBIN_TOKEN_DEL(const ROBIN_TOKEN_DEL *);
int copy_ROBIN_TOKEN_DEL(const ROBIN_TOKEN_DEL *, ROBIN_TOKEN_DEL *);


/*
ROBIN-COMPOUND ::= [APPLICATION 130] SEQUENCE {
  hdr[0]          RobinHeader
}
*/

typedef struct  {
  RobinHeader hdr;
} ROBIN_COMPOUND;

int enc_ROBIN_COMPOUND(unsigned char *, size_t, const ROBIN_COMPOUND *, size_t *);
int    dec_ROBIN_COMPOUND(const unsigned char *, size_t, ROBIN_COMPOUND *, size_t *);
void free_ROBIN_COMPOUND  (ROBIN_COMPOUND *);
size_t len_ROBIN_COMPOUND(const ROBIN_COMPOUND *);
int copy_ROBIN_COMPOUND(const ROBIN_COMPOUND *, ROBIN_COMPOUND *);


/*
ROBIN-DISK-INITIALIZE ::= [APPLICATION 140] SEQUENCE {
  hdr[0]          RobinHeader,
  disk[1]         RobinDisk,
  flags[2]        RobinDiskFlags
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisk disk;
  RobinDiskFlags flags;
} ROBIN_DISK_INITIALIZE;

int enc_ROBIN_DISK_INITIALIZE(unsigned char *, size_t, const ROBIN_DISK_INITIALIZE *, size_t *);
int    dec_ROBIN_DISK_INITIALIZE(const unsigned char *, size_t, ROBIN_DISK_INITIALIZE *, size_t *);
void free_ROBIN_DISK_INITIALIZE  (ROBIN_DISK_INITIALIZE *);
size_t len_ROBIN_DISK_INITIALIZE(const ROBIN_DISK_INITIALIZE *);
int copy_ROBIN_DISK_INITIALIZE(const ROBIN_DISK_INITIALIZE *, ROBIN_DISK_INITIALIZE *);


/*
ROBIN-DISK-MODIFY ::= [APPLICATION 141] SEQUENCE {
  hdr[0]          RobinHeader,
  disk[1]         RobinDisk,
  flags[2]        RobinDiskFlags OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisk disk;
  RobinDiskFlags *flags;
} ROBIN_DISK_MODIFY;

int enc_ROBIN_DISK_MODIFY(unsigned char *, size_t, const ROBIN_DISK_MODIFY *, size_t *);
int    dec_ROBIN_DISK_MODIFY(const unsigned char *, size_t, ROBIN_DISK_MODIFY *, size_t *);
void free_ROBIN_DISK_MODIFY  (ROBIN_DISK_MODIFY *);
size_t len_ROBIN_DISK_MODIFY(const ROBIN_DISK_MODIFY *);
int copy_ROBIN_DISK_MODIFY(const ROBIN_DISK_MODIFY *, ROBIN_DISK_MODIFY *);


/*
ROBIN-DISK-RECOVER ::= [APPLICATION 142] SEQUENCE {
  hdr[0]          RobinHeader,
  disk[1]         RobinDisk,
  flags[2]        RobinDiskFlags OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisk disk;
  RobinDiskFlags *flags;
} ROBIN_DISK_RECOVER;

int enc_ROBIN_DISK_RECOVER(unsigned char *, size_t, const ROBIN_DISK_RECOVER *, size_t *);
int    dec_ROBIN_DISK_RECOVER(const unsigned char *, size_t, ROBIN_DISK_RECOVER *, size_t *);
void free_ROBIN_DISK_RECOVER  (ROBIN_DISK_RECOVER *);
size_t len_ROBIN_DISK_RECOVER(const ROBIN_DISK_RECOVER *);
int copy_ROBIN_DISK_RECOVER(const ROBIN_DISK_RECOVER *, ROBIN_DISK_RECOVER *);


/*
ROBIN-DISK-BALANCE ::= [APPLICATION 143] SEQUENCE {
  hdr[0]          RobinHeader,
  disk[1]         RobinDisk,
  flags[2]        RobinDiskFlags OPTIONAL,
  target[3]       RobinDiskTarget
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisk disk;
  RobinDiskFlags *flags;
  RobinDiskTarget target;
} ROBIN_DISK_BALANCE;

int enc_ROBIN_DISK_BALANCE(unsigned char *, size_t, const ROBIN_DISK_BALANCE *, size_t *);
int    dec_ROBIN_DISK_BALANCE(const unsigned char *, size_t, ROBIN_DISK_BALANCE *, size_t *);
void free_ROBIN_DISK_BALANCE  (ROBIN_DISK_BALANCE *);
size_t len_ROBIN_DISK_BALANCE(const ROBIN_DISK_BALANCE *);
int copy_ROBIN_DISK_BALANCE(const ROBIN_DISK_BALANCE *, ROBIN_DISK_BALANCE *);


/*
ROBIN-DISK-POWERUP ::= [APPLICATION 144] SEQUENCE {
  hdr[0]          RobinHeader,
  disk[1]         RobinDisk,
  flags[2]        RobinDiskFlags OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisk disk;
  RobinDiskFlags *flags;
} ROBIN_DISK_POWERUP;

int enc_ROBIN_DISK_POWERUP(unsigned char *, size_t, const ROBIN_DISK_POWERUP *, size_t *);
int    dec_ROBIN_DISK_POWERUP(const unsigned char *, size_t, ROBIN_DISK_POWERUP *, size_t *);
void free_ROBIN_DISK_POWERUP  (ROBIN_DISK_POWERUP *);
size_t len_ROBIN_DISK_POWERUP(const ROBIN_DISK_POWERUP *);
int copy_ROBIN_DISK_POWERUP(const ROBIN_DISK_POWERUP *, ROBIN_DISK_POWERUP *);


/*
ROBIN-DISK-POWERDOWN ::= [APPLICATION 145] SEQUENCE {
  hdr[0]          RobinHeader,
  disk[1]         RobinDisk,
  flags[2]        RobinDiskFlags OPTIONAL
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinDisk disk;
  RobinDiskFlags *flags;
} ROBIN_DISK_POWERDOWN;

int enc_ROBIN_DISK_POWERDOWN(unsigned char *, size_t, const ROBIN_DISK_POWERDOWN *, size_t *);
int    dec_ROBIN_DISK_POWERDOWN(const unsigned char *, size_t, ROBIN_DISK_POWERDOWN *, size_t *);
void free_ROBIN_DISK_POWERDOWN  (ROBIN_DISK_POWERDOWN *);
size_t len_ROBIN_DISK_POWERDOWN(const ROBIN_DISK_POWERDOWN *);
int copy_ROBIN_DISK_POWERDOWN(const ROBIN_DISK_POWERDOWN *, ROBIN_DISK_POWERDOWN *);


/*
ROBIN-PROTECT-GET ::= [APPLICATION 150] SEQUENCE {
  hdr[0]          RobinHeader,
  source[1]       RobinProtectSource
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinProtectSource source;
} ROBIN_PROTECT_GET;

int enc_ROBIN_PROTECT_GET(unsigned char *, size_t, const ROBIN_PROTECT_GET *, size_t *);
int    dec_ROBIN_PROTECT_GET(const unsigned char *, size_t, ROBIN_PROTECT_GET *, size_t *);
void free_ROBIN_PROTECT_GET  (ROBIN_PROTECT_GET *);
size_t len_ROBIN_PROTECT_GET(const ROBIN_PROTECT_GET *);
int copy_ROBIN_PROTECT_GET(const ROBIN_PROTECT_GET *, ROBIN_PROTECT_GET *);


/*
ROBIN-PROTECT-ADD ::= [APPLICATION 151] SEQUENCE {
  hdr[0]          RobinHeader,
  rules[1]        RobinProtectNodes
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinProtectNodes rules;
} ROBIN_PROTECT_ADD;

int enc_ROBIN_PROTECT_ADD(unsigned char *, size_t, const ROBIN_PROTECT_ADD *, size_t *);
int    dec_ROBIN_PROTECT_ADD(const unsigned char *, size_t, ROBIN_PROTECT_ADD *, size_t *);
void free_ROBIN_PROTECT_ADD  (ROBIN_PROTECT_ADD *);
size_t len_ROBIN_PROTECT_ADD(const ROBIN_PROTECT_ADD *);
int copy_ROBIN_PROTECT_ADD(const ROBIN_PROTECT_ADD *, ROBIN_PROTECT_ADD *);


/*
ROBIN-PROTECT-DEL ::= [APPLICATION 152] SEQUENCE {
  hdr[0]          RobinHeader,
  rules[1]        RobinProtectNodes
}
*/

typedef struct  {
  RobinHeader hdr;
  RobinProtectNodes rules;
} ROBIN_PROTECT_DEL;

int enc_ROBIN_PROTECT_DEL(unsigned char *, size_t, const ROBIN_PROTECT_DEL *, size_t *);
int    dec_ROBIN_PROTECT_DEL(const unsigned char *, size_t, ROBIN_PROTECT_DEL *, size_t *);
void free_ROBIN_PROTECT_DEL  (ROBIN_PROTECT_DEL *);
size_t len_ROBIN_PROTECT_DEL(const ROBIN_PROTECT_DEL *);
int copy_ROBIN_PROTECT_DEL(const ROBIN_PROTECT_DEL *, ROBIN_PROTECT_DEL *);


#endif /* __robin_asn1_h__ */
