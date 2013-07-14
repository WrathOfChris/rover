#	$Gateweaver: Makefile,v 1.41 2007/05/05 17:23:53 cmaxwell Exp $

LIB=	pigeon
SRCS=	pigeon.c dns.c robin_api.c \
		robin_err.c ${ASN1FILES} robin.c robin_connect.c robin_util.c \
		robin_hostmsg.c robin_state.c robin_print.c \
		robin_api_msg.c robin_api_host.c robin_api_user.c
HDRS=	pigeon.h dns.h robin.h \
		generated/robin_api_msg.h generated/robin_api_host.h \
		generated/robin_api_user.h
NOMAN=	pigeon.3
CFLAGS+=-I${.CURDIR} -I.
SRCS+=	parse.c

# asn1 generation
GENERATED=${.CURDIR}/generated
.PATH:	${GENERATED}
ASN1FILES!=cat ${GENERATED}/asn1_files | sed 's,\.x,\.c,g'
CFLAGS+=-I${GENERATED}

# XXX WARNING XXX
# This is just a debug option for testing.  All clients must have this set
# equally, as it is NOT negotiated (yet)
#CFLAGS+= -DPIGEON_ENCRYPT=0 -DPIGEON_SIGN=0

# XXX default loglevel, 4 == state timing
CFLAGS+= -DROBIN_LOGLEVEL=4

# XXX enable testing of PING/PONG without macros
# CFLAGS+= -DDEBUG_TESTFUNC

#
# XXX RELEASE OPTIONS XXX
#
CFLAGS+= -DROBIN_RANDOM_XID

CFLAGS+= -Wall -I${DESTDIR}/usr/include/kerberosV
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wpointer-arith #-Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= #-Werror #-Wshadow

BINDIR?=			/usr/bin
TBASN1_COMPILE?=	${BINDIR}/tbasn1_compile
TBERROR_COMPILE?=	${BINDIR}/compile_et

DPADD+=	${LIBEVENT} ${LIBGSSAPI} ${LIBUTIL}
LDADD+= -levent -lgssapi -lutil

MLINKS=\
	pigeon.3 pigeon_breed.3 \
	pigeon.3 pigeon_write.3 \
	pigeon.3 pigeon_connect.3 \
	pigeon.3 pigeon_print_clientname.3 \
	pigeon.3 pigeon_print_servername.3 \
	pigeon.3 pigeon_print_canon.3 \
	pigeon.3 pigeon_shutdown.3 \
	pigeon.3 pigeon_set_ccache.3 \
	pigeon.3 pigeon_set_shutdown.3 \
	pigeon.3 pigeon_connect_s.3 \
	pigeon.3 pigeon_wait.3

includes:
	@cd ${.CURDIR}; for i in $(HDRS); do \
		b=`basename $$i` ; \
	    j="cmp -s $$i ${DESTDIR}/usr/include/$$b || \
		${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m 444 \
			$$i ${DESTDIR}/usr/include" ; \
	    echo $$j; \
	    eval "$$j"; \
	done

regen_err:
	cd ${GENERATED}; \
		${TBERROR_COMPILE} ${.CURDIR}/robin_err.et

regen_asn1:
	-rm ${GENERATED}/robin_api_msg.c
	-rm ${GENERATED}/robin_api_msg.h
	-rm ${GENERATED}/robin_api_host.c
	-rm ${GENERATED}/robin_api_host.h
	-rm ${GENERATED}/robin_api_user.c
	-rm ${GENERATED}/robin_api_user.h
	cd ${GENERATED}; \
		DEBUG="${DEBUG}" \
			${.CURDIR}/apiext.sh FAKE FAKE PREAMBLE ; \
		DEBUG="${DEBUG}" \
			${TBASN1_COMPILE} -x ${.CURDIR}/apiext.sh \
			${.CURDIR}/robin.asn1 robin_asn1 ; \
		for f in `cat asn1_files`; do \
			mv $$f `echo $$f | sed s,.x$$,.c,g`; \
		done ; \
		DEBUG="${DEBUG}" \
			${.CURDIR}/apiext.sh FAKE FAKE POSTFIX

regen_api:
	CURDIR=${.CURDIR} ${.CURDIR}/apigen.sh \
		>${GENERATED}/robin_api.c \
		3>${GENERATED}/robin_api.h

regen: regen_err regen_asn1 regen_api

.include <bsd.lib.mk>
