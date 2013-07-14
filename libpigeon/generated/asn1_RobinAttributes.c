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
enc_RobinAttributes(unsigned char *p, size_t len, const RobinAttributes *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->family)
{
int oldret = ret;
ret = 0;
e = enc_RobinFamily(p, len, (data)->family, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l);
BACK;
ret += oldret;
}
if ((data)->size)
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, (data)->size, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l);
BACK;
ret += oldret;
}
if ((data)->ctime)
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, (data)->ctime, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l);
BACK;
ret += oldret;
}
if ((data)->atime)
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, (data)->atime, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
if ((data)->mtime)
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, (data)->mtime, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
if ((data)->acl)
{
int oldret = ret;
ret = 0;
e = enc_RobinAcl(p, len, (data)->acl, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
if ((data)->type)
{
int oldret = ret;
ret = 0;
e = enc_ROBIN_TYPE(p, len, (data)->type, &l);
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
dec_RobinAttributes(const unsigned char *p, size_t len, RobinAttributes *data, size_t *size)
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
(data)->type = NULL;
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
(data)->type = malloc(sizeof(*(data)->type));
if ((data)->type == NULL) return ENOMEM;
e = dec_ROBIN_TYPE(p, len, (data)->type, &l);
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
(data)->acl = NULL;
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
(data)->acl = malloc(sizeof(*(data)->acl));
if ((data)->acl == NULL) return ENOMEM;
e = dec_RobinAcl(p, len, (data)->acl, &l);
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
(data)->mtime = NULL;
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
(data)->mtime = malloc(sizeof(*(data)->mtime));
if ((data)->mtime == NULL) return ENOMEM;
e = dec_RobinTime(p, len, (data)->mtime, &l);
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
(data)->atime = NULL;
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
(data)->atime = malloc(sizeof(*(data)->atime));
if ((data)->atime == NULL) return ENOMEM;
e = dec_RobinTime(p, len, (data)->atime, &l);
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
(data)->ctime = NULL;
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
(data)->ctime = malloc(sizeof(*(data)->ctime));
if ((data)->ctime == NULL) return ENOMEM;
e = dec_RobinTime(p, len, (data)->ctime, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 6, &l);
if (e)
(data)->family = NULL;
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
(data)->family = malloc(sizeof(*(data)->family));
if ((data)->family == NULL) return ENOMEM;
e = dec_RobinFamily(p, len, (data)->family, &l);
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
free_RobinAttributes(data);
return e;
}

void
free_RobinAttributes(RobinAttributes *data)
{
if ((data)->type) {
free_ROBIN_TYPE((data)->type);
free((data)->type);
(data)->type = NULL;
}
if ((data)->acl) {
free_RobinAcl((data)->acl);
free((data)->acl);
(data)->acl = NULL;
}
if ((data)->mtime) {
free_RobinTime((data)->mtime);
free((data)->mtime);
(data)->mtime = NULL;
}
if ((data)->atime) {
free_RobinTime((data)->atime);
free((data)->atime);
(data)->atime = NULL;
}
if ((data)->ctime) {
free_RobinTime((data)->ctime);
free((data)->ctime);
(data)->ctime = NULL;
}
if ((data)->size) {
free((data)->size);
(data)->size = NULL;
}
if ((data)->family) {
free_RobinFamily((data)->family);
free((data)->family);
(data)->family = NULL;
}
}

size_t
len_RobinAttributes(const RobinAttributes *data)
{
size_t ret = 0;
if((data)->type){
int oldret = ret;
ret = 0;
ret += len_ROBIN_TYPE((data)->type);
ret += 1 + len_len(ret) + oldret;
}
if((data)->acl){
int oldret = ret;
ret = 0;
ret += len_RobinAcl((data)->acl);
ret += 1 + len_len(ret) + oldret;
}
if((data)->mtime){
int oldret = ret;
ret = 0;
ret += len_RobinTime((data)->mtime);
ret += 1 + len_len(ret) + oldret;
}
if((data)->atime){
int oldret = ret;
ret = 0;
ret += len_RobinTime((data)->atime);
ret += 1 + len_len(ret) + oldret;
}
if((data)->ctime){
int oldret = ret;
ret = 0;
ret += len_RobinTime((data)->ctime);
ret += 1 + len_len(ret) + oldret;
}
if((data)->size){
int oldret = ret;
ret = 0;
ret += len_int64((data)->size);
ret += 1 + len_len(ret) + oldret;
}
if((data)->family){
int oldret = ret;
ret = 0;
ret += len_RobinFamily((data)->family);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinAttributes(const RobinAttributes *from, RobinAttributes *to)
{
if ((from)->type) {
(to)->type = malloc(sizeof(*(to)->type));
if ((to)->type == NULL) return ENOMEM;
if (copy_ROBIN_TYPE((from)->type, (to)->type)) return ENOMEM;
} else
(to)->type = NULL;
if ((from)->acl) {
(to)->acl = malloc(sizeof(*(to)->acl));
if ((to)->acl == NULL) return ENOMEM;
if (copy_RobinAcl((from)->acl, (to)->acl)) return ENOMEM;
} else
(to)->acl = NULL;
if ((from)->mtime) {
(to)->mtime = malloc(sizeof(*(to)->mtime));
if ((to)->mtime == NULL) return ENOMEM;
if (copy_RobinTime((from)->mtime, (to)->mtime)) return ENOMEM;
} else
(to)->mtime = NULL;
if ((from)->atime) {
(to)->atime = malloc(sizeof(*(to)->atime));
if ((to)->atime == NULL) return ENOMEM;
if (copy_RobinTime((from)->atime, (to)->atime)) return ENOMEM;
} else
(to)->atime = NULL;
if ((from)->ctime) {
(to)->ctime = malloc(sizeof(*(to)->ctime));
if ((to)->ctime == NULL) return ENOMEM;
if (copy_RobinTime((from)->ctime, (to)->ctime)) return ENOMEM;
} else
(to)->ctime = NULL;
if ((from)->size) {
(to)->size = malloc(sizeof(*(to)->size));
if ((to)->size == NULL) return ENOMEM;
*((to)->size) = *((from)->size);
} else
(to)->size = NULL;
if ((from)->family) {
(to)->family = malloc(sizeof(*(to)->family));
if ((to)->family == NULL) return ENOMEM;
if (copy_RobinFamily((from)->family, (to)->family)) return ENOMEM;
} else
(to)->family = NULL;
return 0;
}

