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
enc_RobinLock(unsigned char *p, size_t len, const RobinLock *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->upper)
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, (data)->upper, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
if ((data)->lower)
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, (data)->lower, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
if ((data)->expiry)
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, (data)->expiry, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_ROBIN_LOCKTYPE(p, len, &(data)->type, &l);
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
dec_RobinLock(const unsigned char *p, size_t len, RobinLock *data, size_t *size)
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
e = dec_ROBIN_LOCKTYPE(p, len, &(data)->type, &l);
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
(data)->expiry = NULL;
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
(data)->expiry = malloc(sizeof(*(data)->expiry));
if ((data)->expiry == NULL) return ENOMEM;
e = dec_RobinTime(p, len, (data)->expiry, &l);
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
(data)->lower = NULL;
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
(data)->lower = malloc(sizeof(*(data)->lower));
if ((data)->lower == NULL) return ENOMEM;
e = dec_int64(p, len, (data)->lower, &l);
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
(data)->upper = NULL;
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
(data)->upper = malloc(sizeof(*(data)->upper));
if ((data)->upper == NULL) return ENOMEM;
e = dec_int64(p, len, (data)->upper, &l);
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
free_RobinLock(data);
return e;
}

void
free_RobinLock(RobinLock *data)
{
free_ROBIN_LOCKTYPE(&(data)->type);
if ((data)->expiry) {
free_RobinTime((data)->expiry);
free((data)->expiry);
(data)->expiry = NULL;
}
if ((data)->lower) {
free((data)->lower);
(data)->lower = NULL;
}
if ((data)->upper) {
free((data)->upper);
(data)->upper = NULL;
}
}

size_t
len_RobinLock(const RobinLock *data)
{
size_t ret = 0;
{
int oldret = ret;
ret = 0;
ret += len_ROBIN_LOCKTYPE(&(data)->type);
ret += 1 + len_len(ret) + oldret;
}
if((data)->expiry){
int oldret = ret;
ret = 0;
ret += len_RobinTime((data)->expiry);
ret += 1 + len_len(ret) + oldret;
}
if((data)->lower){
int oldret = ret;
ret = 0;
ret += len_int64((data)->lower);
ret += 1 + len_len(ret) + oldret;
}
if((data)->upper){
int oldret = ret;
ret = 0;
ret += len_int64((data)->upper);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinLock(const RobinLock *from, RobinLock *to)
{
if (copy_ROBIN_LOCKTYPE(&(from)->type, &(to)->type)) return ENOMEM;
if ((from)->expiry) {
(to)->expiry = malloc(sizeof(*(to)->expiry));
if ((to)->expiry == NULL) return ENOMEM;
if (copy_RobinTime((from)->expiry, (to)->expiry)) return ENOMEM;
} else
(to)->expiry = NULL;
if ((from)->lower) {
(to)->lower = malloc(sizeof(*(to)->lower));
if ((to)->lower == NULL) return ENOMEM;
*((to)->lower) = *((from)->lower);
} else
(to)->lower = NULL;
if ((from)->upper) {
(to)->upper = malloc(sizeof(*(to)->upper));
if ((to)->upper == NULL) return ENOMEM;
*((to)->upper) = *((from)->upper);
} else
(to)->upper = NULL;
return 0;
}

