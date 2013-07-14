#!/bin/sh

exec 3>>./robin_api_msg.h
exec 4>>./robin_api_msg.c
exec 5>>./robin_api_host.h
exec 6>>./robin_api_host.c
exec 7>>./robin_api_user.h
exec 8>>./robin_api_user.c

NAME=$1
FILE=$2
TYPE=$3

_DATA=

# DEBUG may be set in the environment.  If set, an instrumented api will be
# built that will log_warnx() + abort() on invalid usage.
[[ -z $DEBUG ]] && DEBUG=

# Provide a lower-case name
typeset -l name=$1

#
# PREAMBLE
#

if [[ $TYPE == "PREAMBLE" ]]; then
	[[ -z $CURDIR ]] && CURDIR=`(cd .. && pwd)`

	# Header preamble
	cat >&3 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_MSG_H
#define ROBIN_API_MSG_H
#include "robin.h"
__EOT

	# Source preamble
	cat >&4 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "robin_locl.h"
__EOT

	# Host header preamble
	cat >&5 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_HOST_H
#define ROBIN_API_HOST_H
#include "robin.h"
__EOT

	# Host source preamble
	cat >&6 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#include "robin_locl.h"
__EOT

	# User header preamble
	cat >&7 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#ifndef ROBIN_API_USER_H
#define ROBIN_API_USER_H
#include "robin.h"
__EOT

	# User source preamble
	cat >&8 <<__EOT
/* \$Gateweaver\$ */
/* Generated from ${CURDIR}/robin.asn1 */
/* Do not edit */
#include "robin_locl.h"
__EOT

	# Do not process any further
	exit 0
fi

#
# POSTFIX
#

if [[ $TYPE == "POSTFIX" ]]; then
	# Header postfix
	_DATA="\

#endif
"
	echo >&3 -n "${_DATA}"
	echo >&5 -n "${_DATA}"
	echo >&7 -n "${_DATA}"

	# Do not process any further
	exit 0
fi

# Only process the APPLICATION types.  These are the wire messages.
[[ $TYPE == "APPLICATION" ]] || exit 0

if [[ ${NAME#ROBIN_STATUS} == ${NAME} && ${NAME} != "ROBIN_PONG" ]]; then
	_REQUEST=1
else
	_REQUEST=0
fi

#
# FUNCTION DECLARATION
#

if [[ ${_REQUEST} == 1 ]]; then
	echo >&3 ""
	echo >&3 "int ${name}_api(robin_context, robin_con, const RobinHost *,"
	echo >&3 "		RCB_${NAME#ROBIN_} *, void *,"
	echo >&3 -n "		const RobinPrincipal *"

	echo >&4 ""
	echo >&4 "int"
	echo >&4 "${name}_api(robin_context context, robin_con con, const RobinHost *host,"
	echo >&4 "		RCB_${NAME#ROBIN_} *callback, void *arg,"
	echo >&4 -n "		const RobinPrincipal *proxyuser"

	echo >&5 ""
	echo >&5 "int ${name}_host(robin_context, const RobinHost *,"
	echo >&5 -n "		RCB_${NAME#ROBIN_} *, void *"

	echo >&6 ""
	echo >&6 "int"
	echo >&6 "${name}_host(robin_context context, const RobinHost *host,"
	echo >&6 -n "		RCB_${NAME#ROBIN_} *callback, void *arg"

	echo >&7 ""
	echo >&7 "int ${name}(robin_context,"
	echo >&7 -n "		RCB_${NAME#ROBIN_} *, void *"

	echo >&8 ""
	echo >&8 "int"
	echo >&8 "${name}(robin_context context,"
	echo >&8 -n "		RCB_${NAME#ROBIN_} *callback, void *arg"
else
	echo >&3 ""
	echo >&3 "int ${name}_reply(robin_context, robin_con, uint32_t,"
	echo >&3 -n "		enum rbn_error_number"

	echo >&4 ""
	echo >&4 "int"
	echo >&4 "${name}_reply(robin_context context, robin_con con, uint32_t xid,"
	echo >&4 -n "		enum rbn_error_number status"
fi

#
# PARAMETER DECLARATION
#

while read type varname pos opt subtype; do
	# Pass by reference for the following:
	# -	optional parameters
	# -	types that begin with 'Robin' like RobinHandle
	# -	application messages that begin with ROBIN
	if [[ $opt == "OPTIONAL" ]]; then
		_OPT="*"
		_CONST="const "
	elif [[ ${type#Robin} != ${type} ]]; then
		_OPT="*"
		_CONST="const "
	elif [[ ${type#ROBIN_} != ${type} && ${subtype} == "APPLICATION" ]]; then
		_OPT="*"
		_CONST="const "
	else
		_OPT=""
		_CONST=""
	fi

	# skip special types
	[[ $type == "RobinHeader" ]] && continue
	[[ $type == "RobinStatus" ]] && continue

	# Rewrite types
	[[ $type == "BOOLEAN" ]] && type="int"
	
	_DATA=","
	echo >&3 "${_DATA}"
	echo >&4 "${_DATA}"
	[[ ${_REQUEST} == 1 ]] && {
		echo >&5 "${_DATA}"
		echo >&6 "${_DATA}"
		echo >&7 "${_DATA}"
		echo >&8 "${_DATA}"
	}

	# Manually rewrite to buf + buflen
	if [[ $type == "OCTETSTRING" ]]; then
		_DATA="\t\tconst unsigned char *, size_t"
		echo >&3 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&5 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&7 -n "${_DATA}"

		_DATA="\t\tconst unsigned char *${varname}, size_t ${varname}len"
		echo >&4 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&6 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&8 -n "${_DATA}"

		continue
	fi

	# Actual parameter declaration
	_DATA="\t\t${_CONST}${type} ${_OPT}${varname}"
	echo >&4 -n "${_DATA}"
	[[ ${_REQUEST} == 1 ]] && echo >&6 -n "${_DATA}"
	[[ ${_REQUEST} == 1 ]] && echo >&8 -n "${_DATA}"

	# Actual header parameter declaration
	_DATA="\t\t${_CONST}${type}"
	echo >&3 -n "${_DATA}"
	[[ -z ${_OPT} ]] || echo >&3 -n " ${_OPT}"

	[[ ${_REQUEST} == 1 ]] && {
		echo >&5 -n "${_DATA}"
		echo >&7 -n "${_DATA}"
		[[ -z ${_OPT} ]] || echo >&5 -n " ${_OPT}"
		[[ -z ${_OPT} ]] || echo >&7 -n " ${_OPT}"
	}

	# Debugging, comment declare the subtype
	[[ ! -z $DEBUG ]] && echo >&3 -n "\t/* ${subtype} */"
	[[ ! -z $DEBUG ]] && echo >&4 -n "\t/* ${subtype} */"
	[[ ${_REQUEST} == 1 ]] && {
		[[ ! -z $DEBUG ]] && echo >&5 -n "\t/* ${subtype} */"
		[[ ! -z $DEBUG ]] && echo >&6 -n "\t/* ${subtype} */"
		[[ ! -z $DEBUG ]] && echo >&7 -n "\t/* ${subtype} */"
		[[ ! -z $DEBUG ]] && echo >&8 -n "\t/* ${subtype} */"
	}

done <$FILE

_DATA=")"
echo >&4 "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&6 "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&8 "${_DATA}"

_DATA=");"
echo >&3 "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&5 "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&7 "${_DATA}"

#
# FUNCTION BODY
#

_DATA="\
{
	struct robin_state *rs;
	${NAME} *msg = NULL;
	int ret = ROBIN_SUCCESS;

"
echo >&4 -n "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&6 "{"
[[ ${_REQUEST} == 1 ]] && echo >&8 "{"

if [[ ${_REQUEST} == 1 ]]; then
	# REQuest messages
	cat >&4 <<__EOT
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(${NAME}))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_send(rs, (RCB_STATE *)robin_api_send_${name#robin_},
			ROBIN_MSG_${NAME#ROBIN_}, &msg->hdr, sizeof(*msg));
	if (host)
		robin_state_set_host(rs, host);
	if (con)
		robin_state_set_con(rs, con);
	robin_state_set_waitreply(rs, (RCB_STATUS *)callback, arg);

	if (proxyuser) {
		if ((msg->hdr.user = calloc(1, sizeof(*msg->hdr.user))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
		if ((ret = copy_RobinPrincipal(proxyuser, msg->hdr.user)))
			goto fail;
	}
__EOT

echo >&6 -n "\treturn ${name}_api(context, NULL, host, callback, arg, NULL"
echo >&8 -n "\treturn ${name}_api(context, NULL, NULL, callback, arg, NULL"

else
	# REPly messages
	cat >&4 <<__EOT
	if (xid == 0)
		return ROBIN_SUCCESS;
	if ((rs = robin_state_alloc(context)) == NULL)
		return ROBIN_API_NOMEM;
	if ((msg = calloc(1, sizeof(${NAME}))) == NULL) {
		ret = ROBIN_API_NOMEM;
		goto fail;
	}
	robin_state_set_reply(rs, con, xid,
			(RCB_STATE *)robin_api_send_${name#robin_}, ROBIN_MSG_${NAME#ROBIN_},
			&msg->rep, sizeof(*msg));
	msg->rep.status = status;

__EOT
fi

#
# COPY PARAMETERS
#

while read type varname pos opt subtype; do

	# Required parameters must be dereferenced
	[[ $opt == "OPTIONAL" ]] && _MSG="msg" || _MSG="&msg"

	# skip special types
	[[ $type == "RobinHeader" ]] && continue
	[[ $type == "RobinStatus" ]] && continue

	# subfunctions are parameter lists
	[[ ${_REQUEST} == 1 ]] && echo >&6 ","
	[[ ${_REQUEST} == 1 ]] && echo >&8 ","

	if [[ $opt == "OPTIONAL" ]]; then
		TABS="\t\t"
		_DATA="\
	if (${varname}) {
		if ((msg->${varname} = calloc(1, sizeof(*msg->${varname}))) == NULL) {
			ret = ENOMEM;
			goto fail;
		}
"
		echo >&4 -n "${_DATA}"
	else
		TABS="\t"
		# Debug instrumentation
		[[ ! -z $DEBUG ]] &&
				[[ $type == "OCTETSTRING" ||
				$subtype == "APPLICATION" ||
				! ${type#Robin} == ${type} ]] && {
			_DATA="\
	if (${varname} == NULL) {
		log_warnx(\"DEBUG: ${NAME}(${type} ${varname}) == NULL\");
		abort();
	}
"
			echo >&4 -n "${_DATA}"
		}
	fi

	# Copy the parameters
	# - octet strings are rewritten to buf + buflen
	# - applicaton messages use the associated copy_TYPE api
	# - types not beginning with 'Robin' are assigned
	# - everything else uses the copy_TYPE api
	if [[ $type == "OCTETSTRING" ]]; then
		# OCTET STRING OPTIONAL must deref
		[[ $opt == "OPTIONAL" ]] && _EXT="->" || _EXT="."

		_DATA="\
${TABS}msg->${varname}${_EXT}length = ${varname}len;
${TABS}if ((msg->${varname}${_EXT}data = malloc(msg->${varname}${_EXT}length)) == NULL)
${TABS}	goto fail;
${TABS}bcopy(${varname}, msg->${varname}${_EXT}data, msg->${varname}${_EXT}length);
"
		echo >&4 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&6 -n "\t\t\t${varname}, ${varname}len"
		[[ ${_REQUEST} == 1 ]] && echo >&8 -n "\t\t\t${varname}, ${varname}len"
	elif [[ $subtype == "APPLICATION" ]]; then
		_DATA="\
${TABS}if ((ret = copy_${type}(${varname}, ${_MSG}->${varname})))
${TABS}	goto fail;
"
		echo >&4 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&6 -n "\t\t\t${varname}"
		[[ ${_REQUEST} == 1 ]] && echo >&8 -n "\t\t\t${varname}"
	elif [[ ${type#Robin} == ${type} ]]; then
		# Optional parameters must be referenced
		[[ $opt == "OPTIONAL" ]] && _OPT="*" || _OPT=""
		_DATA="\
${TABS}${_OPT}msg->${varname} = ${_OPT}${varname};
"
		echo >&4 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&6 -n "\t\t\t${varname}"
		[[ ${_REQUEST} == 1 ]] && echo >&8 -n "\t\t\t${varname}"
	else
		_DATA="\
${TABS}if ((ret = copy_${type}(${varname}, ${_MSG}->${varname})))
${TABS}	goto fail;
"
		echo >&4 -n "${_DATA}"
		[[ ${_REQUEST} == 1 ]] && echo >&6 -n "\t\t\t${varname}"
		[[ ${_REQUEST} == 1 ]] && echo >&8 -n "\t\t\t${varname}"
	fi

	# Optional copy block termination
	[[ $opt == "OPTIONAL" ]] && {
		_DATA="\t}"
		echo >&4 "${_DATA}"
	}

done <$FILE

# terminate call list
[[ ${_REQUEST} == 1 ]] && echo >&6 ");"
[[ ${_REQUEST} == 1 ]] && echo >&8 ");"

if [[ ${NAME#ROBIN_STATUS} == ${NAME} && ${NAME} != "ROBIN_PONG" ]]; then
	# REQuest messages
	_DATA="\

	if ((ret = robin_state_go(rs)))
		return ret;
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
"
	echo >&4 -n "${_DATA}"
else
	# REPly messages
	cat >&4 <<__EOT

	if ((ret = robin_state_go(rs)))
		return ret;
	if ((ret = robin_state_find(context, con, xid, &rs)) == ROBIN_SUCCESS)
		robin_state_free(rs);
	return ROBIN_SUCCESS;

fail:
	robin_state_free(rs);
	return ret;
__EOT
fi

_DATA="}"
echo >&4 "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&6 "${_DATA}"
[[ ${_REQUEST} == 1 ]] && echo >&8 "${_DATA}"

exit 0
