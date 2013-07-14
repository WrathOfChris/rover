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
enc_ROBIN_VOLUME_CREATE(unsigned char *p, size_t len, const ROBIN_VOLUME_CREATE *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->rules)
{
int oldret = ret;
ret = 0;
e = enc_RobinProtectNodes(p, len, (data)->rules, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l);
BACK;
ret += oldret;
}
if ((data)->token)
{
int oldret = ret;
ret = 0;
e = enc_RobinToken(p, len, (data)->token, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l);
BACK;
ret += oldret;
}
if ((data)->name)
{
int oldret = ret;
ret = 0;
e = enc_RobinFilename(p, len, (data)->name, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinQuota(p, len, &(data)->quota, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinAttributes(p, len, &(data)->attr, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinHandle(p, len, &(data)->vhdl, &l);
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
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_APPL, CONS, 102, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_VOLUME_CREATE(const unsigned char *p, size_t len, ROBIN_VOLUME_CREATE *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_APPL, CONS, 102, &reallen, &l);
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
e = dec_RobinHandle(p, len, &(data)->vhdl, &l);
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
e = dec_RobinQuota(p, len, &(data)->quota, &l);
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
(data)->name = NULL;
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
(data)->name = malloc(sizeof(*(data)->name));
if ((data)->name == NULL) return ENOMEM;
e = dec_RobinFilename(p, len, (data)->name, &l);
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
(data)->token = NULL;
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
(data)->token = malloc(sizeof(*(data)->token));
if ((data)->token == NULL) return ENOMEM;
e = dec_RobinToken(p, len, (data)->token, &l);
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
(data)->rules = NULL;
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
(data)->rules = malloc(sizeof(*(data)->rules));
if ((data)->rules == NULL) return ENOMEM;
e = dec_RobinProtectNodes(p, len, (data)->rules, &l);
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
free_ROBIN_VOLUME_CREATE(data);
return e;
}

void
free_ROBIN_VOLUME_CREATE(ROBIN_VOLUME_CREATE *data)
{
free_RobinHeader(&(data)->hdr);
free_RobinHandle(&(data)->vhdl);
free_RobinAttributes(&(data)->attr);
free_RobinQuota(&(data)->quota);
if ((data)->name) {
free_RobinFilename((data)->name);
free((data)->name);
(data)->name = NULL;
}
if ((data)->token) {
free_RobinToken((data)->token);
free((data)->token);
(data)->token = NULL;
}
if ((data)->rules) {
free_RobinProtectNodes((data)->rules);
free((data)->rules);
(data)->rules = NULL;
}
}

size_t
len_ROBIN_VOLUME_CREATE(const ROBIN_VOLUME_CREATE *data)
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
ret += len_RobinHandle(&(data)->vhdl);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinAttributes(&(data)->attr);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinQuota(&(data)->quota);
ret += 1 + len_len(ret) + oldret;
}
if((data)->name){
int oldret = ret;
ret = 0;
ret += len_RobinFilename((data)->name);
ret += 1 + len_len(ret) + oldret;
}
if((data)->token){
int oldret = ret;
ret = 0;
ret += len_RobinToken((data)->token);
ret += 1 + len_len(ret) + oldret;
}
if((data)->rules){
int oldret = ret;
ret = 0;
ret += len_RobinProtectNodes((data)->rules);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
ret += 2 + len_len (ret);
return ret;
}

int
copy_ROBIN_VOLUME_CREATE(const ROBIN_VOLUME_CREATE *from, ROBIN_VOLUME_CREATE *to)
{
if (copy_RobinHeader(&(from)->hdr, &(to)->hdr)) return ENOMEM;
if (copy_RobinHandle(&(from)->vhdl, &(to)->vhdl)) return ENOMEM;
if (copy_RobinAttributes(&(from)->attr, &(to)->attr)) return ENOMEM;
if (copy_RobinQuota(&(from)->quota, &(to)->quota)) return ENOMEM;
if ((from)->name) {
(to)->name = malloc(sizeof(*(to)->name));
if ((to)->name == NULL) return ENOMEM;
if (copy_RobinFilename((from)->name, (to)->name)) return ENOMEM;
} else
(to)->name = NULL;
if ((from)->token) {
(to)->token = malloc(sizeof(*(to)->token));
if ((to)->token == NULL) return ENOMEM;
if (copy_RobinToken((from)->token, (to)->token)) return ENOMEM;
} else
(to)->token = NULL;
if ((from)->rules) {
(to)->rules = malloc(sizeof(*(to)->rules));
if ((to)->rules == NULL) return ENOMEM;
if (copy_RobinProtectNodes((from)->rules, (to)->rules)) return ENOMEM;
} else
(to)->rules = NULL;
return 0;
}

