/* $Gateweaver: dns.h,v 1.2 2005/08/15 21:03:36 cmaxwell Exp $ */
#ifndef DNS_H
#define DNS_H
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/nameser.h>
#include <event.h>

#define DNS_MAXPACKET	(64 * 1024)

#define DNS_EVTYPE(t)	\
	(	(t == EV_TIMEOUT) ? "TIMEOUT"	\
	:	(t == EV_READ) ? "READ"			\
	:	(t == EV_WRITE) ? "WRITE"		\
	:	"INVALID")

/*
 * Query return types
 */
struct dnsq_a {
	struct sockaddr_storage ss;
};
struct dnsq_ns {
	char name[MAXHOSTNAMELEN];
};
struct dnsq_cname {
	char name[MAXHOSTNAMELEN];
};
struct dnsq_soa {
	char mname[MAXDNAME];
	char rname[MAXDNAME];
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};
struct dnsq_ptr {
	char name[MAXHOSTNAMELEN];
};
struct dnsq_mx {
	uint16_t pref;
	char name[MAXHOSTNAMELEN];
};
struct dnsq_txt {
	char data[MAXDNAME];
};
struct dnsq_srv {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	char name[MAXHOSTNAMELEN];
};

struct dns_data {
	TAILQ_ENTRY(dns_data) entry;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;

	unsigned char name[MAXDNAME];

	union {
		struct dnsq_a a;
		struct dnsq_ns ns;
		struct dnsq_cname cname;
		struct dnsq_soa soa;
		struct dnsq_ptr ptr;
		struct dnsq_mx mx;
		struct dnsq_txt txt;
		struct dnsq_srv srv;
	} data;
};
TAILQ_HEAD(dns_data_list, dns_data);

/*
 * Query kept in a searchable list,
 * Keeps a server pointer to the current server
 */
#define DNS_MODE_NONE		0
#define DNS_MODE_UDP		1
#define DNS_MODE_TCP		2
#define DNS_MODE_CONNECT	3
struct dns_query {
	TAILQ_ENTRY(dns_query) entry;
	uint16_t id;	/* network byte order */
	uint8_t trys;
	uint8_t mode;
	int q_errno;

	struct dns_nameserver *server;
	unsigned char *querybuf;
	unsigned char *query;
	size_t qlen;
	time_t ttl;		/* time until query to this server invalid */

	uint8_t sent;
	void *callback_arg;
	void (*callback)(struct dns_query *, void *);

	struct dns_data_list q_question;
	struct dns_data_list q_answer;
	struct dns_data_list q_authority;
	struct dns_data_list q_additional;
};
TAILQ_HEAD(dns_query_list, dns_query);

struct dns_nameserver {
	TAILQ_ENTRY(dns_nameserver) entry;
	struct sockaddr_storage ss;
	struct {
		int fd;
		int mode;
		struct event evr;
		struct event evw;
	} tcp, udp;
	time_t ttl;		/* time until ss is no longer valid */

	struct dns_query_list qq;
};
TAILQ_HEAD(dns_nameserver_list, dns_nameserver);

int dns_init(void);
int dns_add_nameserver(struct sockaddr *);
void dns_abort_byarg(void *);

int dns_mux(const char *, int, void (*)(struct dns_query *, void *), void *);
int dns_rptr(struct sockaddr *, void (*)(struct dns_query *, void *), void *);
#define dns_a(name, cb, arg)		dns_mux((name), T_A, (cb), (arg))
#define dns_aaaa(name, cb, arg)		dns_mux((name), T_AAAA, (cb), (arg))
#define dns_mx(name, cb, arg)		dns_mux((name), T_MX, (cb), (arg))
#define dns_ptr(name, cb, arg)		dns_mux((name), T_PTR, (cb), (arg))
#define dns_soa(name, cb, arg)		dns_mux((name), T_SOA, (cb), (arg))
#define dns_txt(name, cb, arg)		dns_mux((name), T_TXT, (cb), (arg))
#define dns_ns(name, cb, arg)		dns_mux((name), T_NS, (cb), (arg))
#define dns_cname(name, cb, arg)	dns_mux((name), T_CNAME, (cb), (arg))
#define dns_srv(name, cb, arg)		dns_mux((name), T_SRV, (cb), (arg))

#endif
