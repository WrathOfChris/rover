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
enc_RobinDiskTarget(unsigned char *p, size_t len, const RobinDiskTarget *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->percent)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->percent, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
if ((data)->size)
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, (data)->size, &l);
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
dec_RobinDiskTarget(const unsigned char *p, size_t len, RobinDiskTarget *data, size_t *size)
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
(data)->size = NULL;
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
(data)->size = malloc(sizeof(*(data)->size));
if ((data)->size == NULL) return ENOMEM;
e = dec_int64(p, len, (data)->size, &l);
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
(data)->percent = NULL;
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
(data)->percent = malloc(sizeof(*(data)->percent));
if ((data)->percent == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->percent, &l);
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
free_RobinDiskTarget(data);
return e;
}

void
free_RobinDiskTarget(RobinDiskTarget *data)
{
if ((data)->size) {
free((data)->size);
(data)->size = NULL;
}
if ((data)->percent) {
free((data)->percent);
(data)->percent = NULL;
}
}

size_t
len_RobinDiskTarget(const RobinDiskTarget *data)
{
size_t ret = 0;
if((data)->size){
int oldret = ret;
ret = 0;
ret += len_int64((data)->size);
ret += 1 + len_len(ret) + oldret;
}
if((data)->percent){
int oldret = ret;
ret = 0;
ret += len_int32((data)->percent);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinDiskTarget(const RobinDiskTarget *from, RobinDiskTarget *to)
{
if ((from)->size) {
(to)->size = malloc(sizeof(*(to)->size));
if ((to)->size == NULL) return ENOMEM;
*((to)->size) = *((from)->size);
} else
(to)->size = NULL;
if ((from)->percent) {
(to)->percent = malloc(sizeof(*(to)->percent));
if ((to)->percent == NULL) return ENOMEM;
*((to)->percent) = *((from)->percent);
} else
(to)->percent = NULL;
return 0;
}

