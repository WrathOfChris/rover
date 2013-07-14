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
enc_RobinProtectSource(unsigned char *p, size_t len, const RobinProtectSource *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->disk)
{
int oldret = ret;
ret = 0;
e = enc_RobinDisk(p, len, (data)->disk, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
if ((data)->vhdl)
{
int oldret = ret;
ret = 0;
e = enc_RobinHandle(p, len, (data)->vhdl, &l);
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
dec_RobinProtectSource(const unsigned char *p, size_t len, RobinProtectSource *data, size_t *size)
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
(data)->vhdl = NULL;
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
(data)->vhdl = malloc(sizeof(*(data)->vhdl));
if ((data)->vhdl == NULL) return ENOMEM;
e = dec_RobinHandle(p, len, (data)->vhdl, &l);
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
(data)->disk = NULL;
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
(data)->disk = malloc(sizeof(*(data)->disk));
if ((data)->disk == NULL) return ENOMEM;
e = dec_RobinDisk(p, len, (data)->disk, &l);
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
free_RobinProtectSource(data);
return e;
}

void
free_RobinProtectSource(RobinProtectSource *data)
{
if ((data)->vhdl) {
free_RobinHandle((data)->vhdl);
free((data)->vhdl);
(data)->vhdl = NULL;
}
if ((data)->disk) {
free_RobinDisk((data)->disk);
free((data)->disk);
(data)->disk = NULL;
}
}

size_t
len_RobinProtectSource(const RobinProtectSource *data)
{
size_t ret = 0;
if((data)->vhdl){
int oldret = ret;
ret = 0;
ret += len_RobinHandle((data)->vhdl);
ret += 1 + len_len(ret) + oldret;
}
if((data)->disk){
int oldret = ret;
ret = 0;
ret += len_RobinDisk((data)->disk);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinProtectSource(const RobinProtectSource *from, RobinProtectSource *to)
{
if ((from)->vhdl) {
(to)->vhdl = malloc(sizeof(*(to)->vhdl));
if ((to)->vhdl == NULL) return ENOMEM;
if (copy_RobinHandle((from)->vhdl, (to)->vhdl)) return ENOMEM;
} else
(to)->vhdl = NULL;
if ((from)->disk) {
(to)->disk = malloc(sizeof(*(to)->disk));
if ((to)->disk == NULL) return ENOMEM;
if (copy_RobinDisk((from)->disk, (to)->disk)) return ENOMEM;
} else
(to)->disk = NULL;
return 0;
}

