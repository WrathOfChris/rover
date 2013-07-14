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
enc_RobinProtectInfo(unsigned char *p, size_t len, const RobinProtectInfo *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
{
int oldret = ret;
ret = 0;
e = enc_RobinProtectTimes(p, len, &(data)->time, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
if ((data)->limit)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->limit, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
if ((data)->want)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->want, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
if ((data)->need)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->need, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l);
BACK;
ret += oldret;
}
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_RobinProtectInfo(const unsigned char *p, size_t len, RobinProtectInfo *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
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
(data)->need = NULL;
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
(data)->need = malloc(sizeof(*(data)->need));
if ((data)->need == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->need, &l);
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
(data)->want = NULL;
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
(data)->want = malloc(sizeof(*(data)->want));
if ((data)->want == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->want, &l);
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
(data)->limit = NULL;
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
(data)->limit = malloc(sizeof(*(data)->limit));
if ((data)->limit == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->limit, &l);
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
e = dec_RobinProtectTimes(p, len, &(data)->time, &l);
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
if (size) *size = ret;
return 0;
fail:
free_RobinProtectInfo(data);
return e;
}

void
free_RobinProtectInfo(RobinProtectInfo *data)
{
if ((data)->need) {
free((data)->need);
(data)->need = NULL;
}
if ((data)->want) {
free((data)->want);
(data)->want = NULL;
}
if ((data)->limit) {
free((data)->limit);
(data)->limit = NULL;
}
free_RobinProtectTimes(&(data)->time);
}

size_t
len_RobinProtectInfo(const RobinProtectInfo *data)
{
size_t ret = 0;
if((data)->need){
int oldret = ret;
ret = 0;
ret += len_int32((data)->need);
ret += 1 + len_len(ret) + oldret;
}
if((data)->want){
int oldret = ret;
ret = 0;
ret += len_int32((data)->want);
ret += 1 + len_len(ret) + oldret;
}
if((data)->limit){
int oldret = ret;
ret = 0;
ret += len_int32((data)->limit);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinProtectTimes(&(data)->time);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinProtectInfo(const RobinProtectInfo *from, RobinProtectInfo *to)
{
if ((from)->need) {
(to)->need = malloc(sizeof(*(to)->need));
if ((to)->need == NULL) return ENOMEM;
*((to)->need) = *((from)->need);
} else
(to)->need = NULL;
if ((from)->want) {
(to)->want = malloc(sizeof(*(to)->want));
if ((to)->want == NULL) return ENOMEM;
*((to)->want) = *((from)->want);
} else
(to)->want = NULL;
if ((from)->limit) {
(to)->limit = malloc(sizeof(*(to)->limit));
if ((to)->limit == NULL) return ENOMEM;
*((to)->limit) = *((from)->limit);
} else
(to)->limit = NULL;
if (copy_RobinProtectTimes(&(from)->time, &(to)->time)) return ENOMEM;
return 0;
}

