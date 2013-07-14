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
enc_ROBIN_MKNODE(unsigned char *p, size_t len, const ROBIN_MKNODE *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->lock)
{
int oldret = ret;
ret = 0;
e = enc_ROBIN_LOCKTYPE(p, len, (data)->lock, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l);
BACK;
ret += oldret;
}
if ((data)->sum)
{
int oldret = ret;
ret = 0;
e = enc_RobinChecksum(p, len, (data)->sum, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinAttributes(p, len, &(data)->attr, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l);
BACK;
ret += oldret;
}
if ((data)->hdl)
{
int oldret = ret;
ret = 0;
e = enc_RobinHandle(p, len, (data)->hdl, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
if ((data)->vhdl)
{
int oldret = ret;
ret = 0;
e = enc_RobinHandle(p, len, (data)->vhdl, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinNodeFlags(p, len, &(data)->flags, &l);
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
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_APPL, CONS, 40, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_MKNODE(const unsigned char *p, size_t len, ROBIN_MKNODE *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_APPL, CONS, 40, &reallen, &l);
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
e = dec_RobinNodeFlags(p, len, &(data)->flags, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 3, &l);
if (e)
(data)->hdl = NULL;
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
(data)->hdl = malloc(sizeof(*(data)->hdl));
if ((data)->hdl == NULL) return ENOMEM;
e = dec_RobinHandle(p, len, (data)->hdl, &l);
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
e = dec_RobinAttributes(p, len, &(data)->attr, &l);
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
(data)->sum = NULL;
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
(data)->sum = malloc(sizeof(*(data)->sum));
if ((data)->sum == NULL) return ENOMEM;
e = dec_RobinChecksum(p, len, (data)->sum, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 6, &l);
if (e)
(data)->lock = NULL;
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
(data)->lock = malloc(sizeof(*(data)->lock));
if ((data)->lock == NULL) return ENOMEM;
e = dec_ROBIN_LOCKTYPE(p, len, (data)->lock, &l);
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
free_ROBIN_MKNODE(data);
return e;
}

void
free_ROBIN_MKNODE(ROBIN_MKNODE *data)
{
free_RobinHeader(&(data)->hdr);
free_RobinNodeFlags(&(data)->flags);
if ((data)->vhdl) {
free_RobinHandle((data)->vhdl);
free((data)->vhdl);
(data)->vhdl = NULL;
}
if ((data)->hdl) {
free_RobinHandle((data)->hdl);
free((data)->hdl);
(data)->hdl = NULL;
}
free_RobinAttributes(&(data)->attr);
if ((data)->sum) {
free_RobinChecksum((data)->sum);
free((data)->sum);
(data)->sum = NULL;
}
if ((data)->lock) {
free_ROBIN_LOCKTYPE((data)->lock);
free((data)->lock);
(data)->lock = NULL;
}
}

size_t
len_ROBIN_MKNODE(const ROBIN_MKNODE *data)
{
size_t ret = 0;
{
int oldret = ret;
ret = 0;
ret += len_RobinHeader(&(data)->hdr);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinNodeFlags(&(data)->flags);
ret += 1 + len_len(ret) + oldret;
}
if((data)->vhdl){
int oldret = ret;
ret = 0;
ret += len_RobinHandle((data)->vhdl);
ret += 1 + len_len(ret) + oldret;
}
if((data)->hdl){
int oldret = ret;
ret = 0;
ret += len_RobinHandle((data)->hdl);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinAttributes(&(data)->attr);
ret += 1 + len_len(ret) + oldret;
}
if((data)->sum){
int oldret = ret;
ret = 0;
ret += len_RobinChecksum((data)->sum);
ret += 1 + len_len(ret) + oldret;
}
if((data)->lock){
int oldret = ret;
ret = 0;
ret += len_ROBIN_LOCKTYPE((data)->lock);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
ret += 2 + len_len (ret);
return ret;
}

int
copy_ROBIN_MKNODE(const ROBIN_MKNODE *from, ROBIN_MKNODE *to)
{
if (copy_RobinHeader(&(from)->hdr, &(to)->hdr)) return ENOMEM;
if (copy_RobinNodeFlags(&(from)->flags, &(to)->flags)) return ENOMEM;
if ((from)->vhdl) {
(to)->vhdl = malloc(sizeof(*(to)->vhdl));
if ((to)->vhdl == NULL) return ENOMEM;
if (copy_RobinHandle((from)->vhdl, (to)->vhdl)) return ENOMEM;
} else
(to)->vhdl = NULL;
if ((from)->hdl) {
(to)->hdl = malloc(sizeof(*(to)->hdl));
if ((to)->hdl == NULL) return ENOMEM;
if (copy_RobinHandle((from)->hdl, (to)->hdl)) return ENOMEM;
} else
(to)->hdl = NULL;
if (copy_RobinAttributes(&(from)->attr, &(to)->attr)) return ENOMEM;
if ((from)->sum) {
(to)->sum = malloc(sizeof(*(to)->sum));
if ((to)->sum == NULL) return ENOMEM;
if (copy_RobinChecksum((from)->sum, (to)->sum)) return ENOMEM;
} else
(to)->sum = NULL;
if ((from)->lock) {
(to)->lock = malloc(sizeof(*(to)->lock));
if ((to)->lock == NULL) return ENOMEM;
if (copy_ROBIN_LOCKTYPE((from)->lock, (to)->lock)) return ENOMEM;
} else
(to)->lock = NULL;
return 0;
}

