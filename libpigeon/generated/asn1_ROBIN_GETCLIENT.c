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
enc_ROBIN_GETCLIENT(unsigned char *p, size_t len, const ROBIN_GETCLIENT *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->principals)
{
int oldret = ret;
ret = 0;
e = enc_RobinPrincipals(p, len, (data)->principals, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
if ((data)->disks)
{
int oldret = ret;
ret = 0;
e = enc_RobinDisks(p, len, (data)->disks, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinHeader(p, len, &(data)->hdr, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 0, &l);
BACK;
ret += oldret;
}
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_UNIV, CONS, UT_Sequence, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_APPL, CONS, 4, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_GETCLIENT(const unsigned char *p, size_t len, ROBIN_GETCLIENT *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_APPL, CONS, 4, &reallen, &l);
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
e = dec_RobinHeader(p, len, &(data)->hdr, &l);
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
(data)->disks = NULL;
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
(data)->disks = malloc(sizeof(*(data)->disks));
if ((data)->disks == NULL) return ENOMEM;
e = dec_RobinDisks(p, len, (data)->disks, &l);
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
(data)->principals = NULL;
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
(data)->principals = malloc(sizeof(*(data)->principals));
if ((data)->principals == NULL) return ENOMEM;
e = dec_RobinPrincipals(p, len, (data)->principals, &l);
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
free_ROBIN_GETCLIENT(data);
return e;
}

void
free_ROBIN_GETCLIENT(ROBIN_GETCLIENT *data)
{
free_RobinHeader(&(data)->hdr);
if ((data)->disks) {
free_RobinDisks((data)->disks);
free((data)->disks);
(data)->disks = NULL;
}
if ((data)->principals) {
free_RobinPrincipals((data)->principals);
free((data)->principals);
(data)->principals = NULL;
}
}

size_t
len_ROBIN_GETCLIENT(const ROBIN_GETCLIENT *data)
{
size_t ret = 0;
{
int oldret = ret;
ret = 0;
ret += len_RobinHeader(&(data)->hdr);
ret += 1 + len_len(ret) + oldret;
}
if((data)->disks){
int oldret = ret;
ret = 0;
ret += len_RobinDisks((data)->disks);
ret += 1 + len_len(ret) + oldret;
}
if((data)->principals){
int oldret = ret;
ret = 0;
ret += len_RobinPrincipals((data)->principals);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
ret += 1 + len_len (ret);
return ret;
}

int
copy_ROBIN_GETCLIENT(const ROBIN_GETCLIENT *from, ROBIN_GETCLIENT *to)
{
if (copy_RobinHeader(&(from)->hdr, &(to)->hdr)) return ENOMEM;
if ((from)->disks) {
(to)->disks = malloc(sizeof(*(to)->disks));
if ((to)->disks == NULL) return ENOMEM;
if (copy_RobinDisks((from)->disks, (to)->disks)) return ENOMEM;
} else
(to)->disks = NULL;
if ((from)->principals) {
(to)->principals = malloc(sizeof(*(to)->principals));
if ((to)->principals == NULL) return ENOMEM;
if (copy_RobinPrincipals((from)->principals, (to)->principals)) return ENOMEM;
} else
(to)->principals = NULL;
return 0;
}

