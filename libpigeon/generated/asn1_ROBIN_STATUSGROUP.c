/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <robin_asn1.h>
#include <toolbox.h>
#include <toolbox_asn1_err.h>
#include <toolbox_asn1_der.h>

#define BACK if (e) return e; p -= l; len -= l; ret += l

int
enc_ROBIN_STATUSGROUP(unsigned char *p, size_t len, const ROBIN_STATUSGROUP *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->users)
{
int oldret = ret;
ret = 0;
e = enc_RobinPrincipals(p, len, (data)->users, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l);
BACK;
ret += oldret;
}
if ((data)->private)
{
int oldret = ret;
ret = 0;
e = enc_RobinGroupRight(p, len, (data)->private, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l);
BACK;
ret += oldret;
}
if ((data)->public)
{
int oldret = ret;
ret = 0;
e = enc_RobinGroupRight(p, len, (data)->public, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
if ((data)->owner)
{
int oldret = ret;
ret = 0;
e = enc_RobinPrincipal(p, len, (data)->owner, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinPrincipal(p, len, &(data)->group, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinStatus(p, len, &(data)->rep, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l);
BACK;
ret += oldret;
}
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_APPL, CONS, 32, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_STATUSGROUP(const unsigned char *p, size_t len, ROBIN_STATUSGROUP *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_APPL, CONS, 32, &reallen, &l);
FORW;
{
int dce_fix = 0;
if (reallen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < reallen) return TBASN1_BAD_FORMAT;
else len = reallen;
e = tb_der_match_tag_and_len(p, len, ASN1_C_UNIV, CONS, UT_Sequence, &reallen, &l);
FORW;
{
int dce_fix = 0;
if (reallen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < reallen) return TBASN1_BAD_FORMAT;
else len = reallen;
{
size_t newlen, oldlen;

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 0, &l);
if (e)
return e;
else {
p += l;
len -= l;
ret += l;
e = tb_der_get_len(p, len, &newlen, &l);
FORW;
{
int dce_fix = 0;
oldlen = len;
if (newlen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < newlen) return TBASN1_BAD_FORMAT;
else len = newlen;
e = dec_RobinStatus(p, len, &(data)->rep, &l);
FORW;
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}else 
len = oldlen - newlen;
}
}
}
{
size_t newlen, oldlen;

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 1, &l);
if (e)
return e;
else {
p += l;
len -= l;
ret += l;
e = tb_der_get_len(p, len, &newlen, &l);
FORW;
{
int dce_fix = 0;
oldlen = len;
if (newlen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < newlen) return TBASN1_BAD_FORMAT;
else len = newlen;
e = dec_RobinPrincipal(p, len, &(data)->group, &l);
FORW;
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}else 
len = oldlen - newlen;
}
}
}
{
size_t newlen, oldlen;

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 2, &l);
if (e)
(data)->owner = NULL;
else {
p += l;
len -= l;
ret += l;
e = tb_der_get_len(p, len, &newlen, &l);
FORW;
{
int dce_fix = 0;
oldlen = len;
if (newlen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < newlen) return TBASN1_BAD_FORMAT;
else len = newlen;
(data)->owner = malloc(sizeof(*(data)->owner));
if ((data)->owner == NULL) return ENOMEM;
e = dec_RobinPrincipal(p, len, (data)->owner, &l);
FORW;
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}else 
len = oldlen - newlen;
}
}
}
{
size_t newlen, oldlen;

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 3, &l);
if (e)
(data)->public = NULL;
else {
p += l;
len -= l;
ret += l;
e = tb_der_get_len(p, len, &newlen, &l);
FORW;
{
int dce_fix = 0;
oldlen = len;
if (newlen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < newlen) return TBASN1_BAD_FORMAT;
else len = newlen;
(data)->public = malloc(sizeof(*(data)->public));
if ((data)->public == NULL) return ENOMEM;
e = dec_RobinGroupRight(p, len, (data)->public, &l);
FORW;
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}else 
len = oldlen - newlen;
}
}
}
{
size_t newlen, oldlen;

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 4, &l);
if (e)
(data)->private = NULL;
else {
p += l;
len -= l;
ret += l;
e = tb_der_get_len(p, len, &newlen, &l);
FORW;
{
int dce_fix = 0;
oldlen = len;
if (newlen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < newlen) return TBASN1_BAD_FORMAT;
else len = newlen;
(data)->private = malloc(sizeof(*(data)->private));
if ((data)->private == NULL) return ENOMEM;
e = dec_RobinGroupRight(p, len, (data)->private, &l);
FORW;
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}else 
len = oldlen - newlen;
}
}
}
{
size_t newlen, oldlen;

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 5, &l);
if (e)
(data)->users = NULL;
else {
p += l;
len -= l;
ret += l;
e = tb_der_get_len(p, len, &newlen, &l);
FORW;
{
int dce_fix = 0;
oldlen = len;
if (newlen == ASN1_INDEFINITE) dce_fix = 1;
else if (len < newlen) return TBASN1_BAD_FORMAT;
else len = newlen;
(data)->users = malloc(sizeof(*(data)->users));
if ((data)->users == NULL) return ENOMEM;
e = dec_RobinPrincipals(p, len, (data)->users, &l);
FORW;
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}else 
len = oldlen - newlen;
}
}
}
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}
}
if (dce_fix){
e = tb_der_match_tag_and_len(p, len, (Der_class)0, (Der_type)0, 0, &reallen, &l);
FORW;
}
}
if (size) *size = ret;
return 0;
fail:
free_ROBIN_STATUSGROUP(data);
return e;
}

void
free_ROBIN_STATUSGROUP(ROBIN_STATUSGROUP *data)
{
free_RobinStatus(&(data)->rep);
free_RobinPrincipal(&(data)->group);
if ((data)->owner) {
free_RobinPrincipal((data)->owner);
free((data)->owner);
(data)->owner = NULL;
}
if ((data)->public) {
free_RobinGroupRight((data)->public);
free((data)->public);
(data)->public = NULL;
}
if ((data)->private) {
free_RobinGroupRight((data)->private);
free((data)->private);
(data)->private = NULL;
}
if ((data)->users) {
free_RobinPrincipals((data)->users);
free((data)->users);
(data)->users = NULL;
}
}

size_t
len_ROBIN_STATUSGROUP(const ROBIN_STATUSGROUP *data)
{
size_t ret = 0;
{
int oldret = ret;
ret = 0;
ret += len_RobinStatus(&(data)->rep);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinPrincipal(&(data)->group);
ret += 1 + len_len(ret) + oldret;
}
if((data)->owner){
int oldret = ret;
ret = 0;
ret += len_RobinPrincipal((data)->owner);
ret += 1 + len_len(ret) + oldret;
}
if((data)->public){
int oldret = ret;
ret = 0;
ret += len_RobinGroupRight((data)->public);
ret += 1 + len_len(ret) + oldret;
}
if((data)->private){
int oldret = ret;
ret = 0;
ret += len_RobinGroupRight((data)->private);
ret += 1 + len_len(ret) + oldret;
}
if((data)->users){
int oldret = ret;
ret = 0;
ret += len_RobinPrincipals((data)->users);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
ret += 2 + len_len (ret);
return ret;
}

int
copy_ROBIN_STATUSGROUP(const ROBIN_STATUSGROUP *from, ROBIN_STATUSGROUP *to)
{
if (copy_RobinStatus(&(from)->rep, &(to)->rep)) return ENOMEM;
if (copy_RobinPrincipal(&(from)->group, &(to)->group)) return ENOMEM;
if ((from)->owner) {
(to)->owner = malloc(sizeof(*(to)->owner));
if ((to)->owner == NULL) return ENOMEM;
if (copy_RobinPrincipal((from)->owner, (to)->owner)) return ENOMEM;
} else
(to)->owner = NULL;
if ((from)->public) {
(to)->public = malloc(sizeof(*(to)->public));
if ((to)->public == NULL) return ENOMEM;
if (copy_RobinGroupRight((from)->public, (to)->public)) return ENOMEM;
} else
(to)->public = NULL;
if ((from)->private) {
(to)->private = malloc(sizeof(*(to)->private));
if ((to)->private == NULL) return ENOMEM;
if (copy_RobinGroupRight((from)->private, (to)->private)) return ENOMEM;
} else
(to)->private = NULL;
if ((from)->users) {
(to)->users = malloc(sizeof(*(to)->users));
if ((to)->users == NULL) return ENOMEM;
if (copy_RobinPrincipals((from)->users, (to)->users)) return ENOMEM;
} else
(to)->users = NULL;
return 0;
}

