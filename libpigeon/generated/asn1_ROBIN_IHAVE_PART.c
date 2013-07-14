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
enc_ROBIN_IHAVE_PART(unsigned char *p, size_t len, const ROBIN_IHAVE_PART *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->tokenkey)
{
int oldret = ret;
ret = 0;
e = enc_RobinEncryptionKey(p, len, (data)->tokenkey, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 15, &l);
BACK;
ret += oldret;
}
if ((data)->curperf)
{
int oldret = ret;
ret = 0;
e = enc_RobinDiskStats(p, len, (data)->curperf, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 14, &l);
BACK;
ret += oldret;
}
if ((data)->totperf)
{
int oldret = ret;
ret = 0;
e = enc_RobinDiskStats(p, len, (data)->totperf, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 13, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinTime(p, len, &(data)->lastmount, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 12, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->maxblock, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 11, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->neednodes, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 10, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->freenodes, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 9, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->usednodes, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 8, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->partnodes, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 7, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->freespace, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->usedspace, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_int64(p, len, &(data)->partspace, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinPartition(p, len, &(data)->partition, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinDiskFlags(p, len, &(data)->diskflags, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
{
int oldret = ret;
ret = 0;
e = enc_RobinRouterFlags(p, len, &(data)->flags, &l);
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
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_APPL, CONS, 90, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_IHAVE_PART(const unsigned char *p, size_t len, ROBIN_IHAVE_PART *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_APPL, CONS, 90, &reallen, &l);
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
e = dec_RobinRouterFlags(p, len, &(data)->flags, &l);
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
e = dec_RobinDiskFlags(p, len, &(data)->diskflags, &l);
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
e = dec_RobinPartition(p, len, &(data)->partition, &l);
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
e = dec_int64(p, len, &(data)->partspace, &l);
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
e = dec_int64(p, len, &(data)->usedspace, &l);
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
e = dec_int64(p, len, &(data)->freespace, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 7, &l);
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
e = dec_int64(p, len, &(data)->partnodes, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 8, &l);
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
e = dec_int64(p, len, &(data)->usednodes, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 9, &l);
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
e = dec_int64(p, len, &(data)->freenodes, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 10, &l);
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
e = dec_int64(p, len, &(data)->neednodes, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 11, &l);
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
e = dec_int64(p, len, &(data)->maxblock, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 12, &l);
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
e = dec_RobinTime(p, len, &(data)->lastmount, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 13, &l);
if (e)
(data)->totperf = NULL;
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
(data)->totperf = malloc(sizeof(*(data)->totperf));
if ((data)->totperf == NULL) return ENOMEM;
e = dec_RobinDiskStats(p, len, (data)->totperf, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 14, &l);
if (e)
(data)->curperf = NULL;
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
(data)->curperf = malloc(sizeof(*(data)->curperf));
if ((data)->curperf == NULL) return ENOMEM;
e = dec_RobinDiskStats(p, len, (data)->curperf, &l);
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

e = tb_der_match_tag(p, len, ASN1_C_CONTEXT, CONS, 15, &l);
if (e)
(data)->tokenkey = NULL;
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
(data)->tokenkey = malloc(sizeof(*(data)->tokenkey));
if ((data)->tokenkey == NULL) return ENOMEM;
e = dec_RobinEncryptionKey(p, len, (data)->tokenkey, &l);
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
free_ROBIN_IHAVE_PART(data);
return e;
}

void
free_ROBIN_IHAVE_PART(ROBIN_IHAVE_PART *data)
{
free_RobinHeader(&(data)->hdr);
free_RobinRouterFlags(&(data)->flags);
free_RobinDiskFlags(&(data)->diskflags);
free_RobinPartition(&(data)->partition);
free_RobinTime(&(data)->lastmount);
if ((data)->totperf) {
free_RobinDiskStats((data)->totperf);
free((data)->totperf);
(data)->totperf = NULL;
}
if ((data)->curperf) {
free_RobinDiskStats((data)->curperf);
free((data)->curperf);
(data)->curperf = NULL;
}
if ((data)->tokenkey) {
free_RobinEncryptionKey((data)->tokenkey);
free((data)->tokenkey);
(data)->tokenkey = NULL;
}
}

size_t
len_ROBIN_IHAVE_PART(const ROBIN_IHAVE_PART *data)
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
ret += len_RobinRouterFlags(&(data)->flags);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinDiskFlags(&(data)->diskflags);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinPartition(&(data)->partition);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->partspace);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->usedspace);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->freespace);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->partnodes);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->usednodes);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->freenodes);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->neednodes);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_int64(&(data)->maxblock);
ret += 1 + len_len(ret) + oldret;
}
{
int oldret = ret;
ret = 0;
ret += len_RobinTime(&(data)->lastmount);
ret += 1 + len_len(ret) + oldret;
}
if((data)->totperf){
int oldret = ret;
ret = 0;
ret += len_RobinDiskStats((data)->totperf);
ret += 1 + len_len(ret) + oldret;
}
if((data)->curperf){
int oldret = ret;
ret = 0;
ret += len_RobinDiskStats((data)->curperf);
ret += 1 + len_len(ret) + oldret;
}
if((data)->tokenkey){
int oldret = ret;
ret = 0;
ret += len_RobinEncryptionKey((data)->tokenkey);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
ret += 2 + len_len (ret);
return ret;
}

int
copy_ROBIN_IHAVE_PART(const ROBIN_IHAVE_PART *from, ROBIN_IHAVE_PART *to)
{
if (copy_RobinHeader(&(from)->hdr, &(to)->hdr)) return ENOMEM;
if (copy_RobinRouterFlags(&(from)->flags, &(to)->flags)) return ENOMEM;
if (copy_RobinDiskFlags(&(from)->diskflags, &(to)->diskflags)) return ENOMEM;
if (copy_RobinPartition(&(from)->partition, &(to)->partition)) return ENOMEM;
*(&(to)->partspace) = *(&(from)->partspace);
*(&(to)->usedspace) = *(&(from)->usedspace);
*(&(to)->freespace) = *(&(from)->freespace);
*(&(to)->partnodes) = *(&(from)->partnodes);
*(&(to)->usednodes) = *(&(from)->usednodes);
*(&(to)->freenodes) = *(&(from)->freenodes);
*(&(to)->neednodes) = *(&(from)->neednodes);
*(&(to)->maxblock) = *(&(from)->maxblock);
if (copy_RobinTime(&(from)->lastmount, &(to)->lastmount)) return ENOMEM;
if ((from)->totperf) {
(to)->totperf = malloc(sizeof(*(to)->totperf));
if ((to)->totperf == NULL) return ENOMEM;
if (copy_RobinDiskStats((from)->totperf, (to)->totperf)) return ENOMEM;
} else
(to)->totperf = NULL;
if ((from)->curperf) {
(to)->curperf = malloc(sizeof(*(to)->curperf));
if ((to)->curperf == NULL) return ENOMEM;
if (copy_RobinDiskStats((from)->curperf, (to)->curperf)) return ENOMEM;
} else
(to)->curperf = NULL;
if ((from)->tokenkey) {
(to)->tokenkey = malloc(sizeof(*(to)->tokenkey));
if ((to)->tokenkey == NULL) return ENOMEM;
if (copy_RobinEncryptionKey((from)->tokenkey, (to)->tokenkey)) return ENOMEM;
} else
(to)->tokenkey = NULL;
return 0;
}

