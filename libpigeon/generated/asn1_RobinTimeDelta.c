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
enc_RobinTimeDelta(unsigned char *p, size_t len, const RobinTimeDelta *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, &(data)->stop, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, &(data)->start, &l);
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
dec_RobinTimeDelta(const unsigned char *p, size_t len, RobinTimeDelta *data, size_t *size)
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
e = dec_RobinTime(p, len, &(data)->start, &l);
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
e = dec_RobinTime(p, len, &(data)->stop, &l);
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
free_RobinTimeDelta(data);
return e;
}

void
free_RobinTimeDelta(RobinTimeDelta *data)
{
free_RobinTime(&(data)->start);
free_RobinTime(&(data)->stop);
}

size_t
len_RobinTimeDelta(const RobinTimeDelta *data)
{
size_t ret = 0;
{
int oldret = ret;
ret = 0;
ret += len_RobinTime(&(data)->start);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinTime(&(data)->stop);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinTimeDelta(const RobinTimeDelta *from, RobinTimeDelta *to)
{
if (copy_RobinTime(&(from)->start, &(to)->start)) return ENOMEM;
if (copy_RobinTime(&(from)->stop, &(to)->stop)) return ENOMEM;
return 0;
}

