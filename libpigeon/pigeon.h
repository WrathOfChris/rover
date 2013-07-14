/* $Gateweaver: pigeon.h,v 1.16 2006/09/13 00:31:22 cmaxwell Exp $ */
#ifndef PIGEON_H
#define PIGEON_H
#include <kerberosV/gssapi.h>

#define PIGEON_TIMEOUT	(1200)
#define PIGEON_NAMELEN	(256)

#ifndef PIGEON_ENCRYPT
#define PIGEON_ENCRYPT	1
#endif

#ifndef PIGEON_SIGN
#define PIGEON_SIGN 	1
#endif

enum gss_state {
	GSS_STATE_NONE,
	GSS_STATE_AUTHCON,
	GSS_STATE_AUTHNEG,
	GSS_STATE_AUTHENTICATED
};

enum pigeon_mode {
	PIGEON_MODE_SERVER,
	PIGEON_MODE_CLIENT,
	PIGEON_MODE_USER,
	PIGEON_MODE_BOTH
};
	
struct gss_context {
	enum gss_state	state;
	OM_uint32		major;
	OM_uint32		minor;
	gss_ctx_id_t	context;
	gss_OID			oid;
	gss_name_t		client_name;
	gss_name_t		server_name;
	gss_cred_id_t	client_creds;
	gss_cred_id_t	server_creds;
	char			*ccache_name;
};

struct pigeon {
	struct bufferevent *bev;
	struct gss_context *ctx;
	uint32_t noencrypt:1,
			 nosign:1,
			 killme:1,
			 xxx:29;
	int shutdown_counter;
	void (*accept)(struct pigeon *, void *);
	void (*process)(struct pigeon *, gss_buffer_desc *, void *);
	void (*shutdown)(struct pigeon *, void *);
	void *arg;
};

struct pigeon *
pigeon_breed(int, const char *, enum pigeon_mode,
		void (*)(struct pigeon *, void *),
		void (*)(struct pigeon *, gss_buffer_desc *, void *),
		void (*)(struct pigeon *, void *),
		void *);
struct pigeon *
pigeon_breed_cleartext(int, const char *, enum pigeon_mode,
		void (*)(struct pigeon *, void *),
		void (*)(struct pigeon *, gss_buffer_desc *, void *),
		void (*)(struct pigeon *, void *),
		void *);
int pigeon_write(struct pigeon *, char *, size_t);
int pigeon_connect(struct pigeon *, const char *);
char * pigeon_print_clientname(struct pigeon *);
char * pigeon_print_servername(struct pigeon *);
char * pigeon_print_canon(struct pigeon *, gss_name_t);
void pigeon_shutdown(struct pigeon **);
void pigeon_set_shutdown(struct pigeon *);
int pigeon_set_ccache(struct pigeon *, const char *);
void pigeon_set_logging(int);
void pigeon_set_timeout(struct pigeon *, time_t);
void pigeon_set_cleartext(struct pigeon *, int, int);

/* simple/sync commands for client utilities */
struct pigeon * pigeon_connect_s(int, const char *, enum pigeon_mode,
		void (*)(struct pigeon *, gss_buffer_desc *, void *));
void pigeon_accept_s(struct pigeon *, void *);
void pigeon_process_s(struct pigeon *, gss_buffer_desc *to, void *);
void pigeon_shutdown_s(struct pigeon *, void *);
int pigeon_wait(void);

int pigeon_isconnected(struct pigeon *);

/* need this for debugging */
#include <stdarg.h>
void log_init(int);
void log_warn(const char *, ...)
	__attribute__ ((__format__(printf, 1, 2)));
void log_warnx(const char *, ...)
	__attribute__ ((__format__(printf, 1, 2)));
void log_info(const char *, ...)
	__attribute__ ((__format__(printf, 1, 2)));
void log_debug(const char *, ...)
	__attribute__ ((__format__(printf, 1, 2)));
__dead void fatal(const char *);
__dead void fatalx(const char *);
void notfatal(const char *);
const char *log_sockaddr(struct sockaddr *);
void log_hexdump(const unsigned char *, size_t)
	__attribute__ ((__bounded__(__buffer__, 1, 2)));
void vlog(int, const char *, va_list)
	__attribute__ ((__format__(printf, 2, 0)));
void log_trace(const unsigned char *, size_t)
	__attribute__ ((__bounded__(__buffer__, 1, 2)));

#endif
