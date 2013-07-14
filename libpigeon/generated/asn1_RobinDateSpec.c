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
enc_RobinDateSpec(unsigned char *p, size_t len, const RobinDateSpec *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
if ((data)->nanosec)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->nanosec, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 7, &l);
BACK;
ret += oldret;
}
if ((data)->second)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->second, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 6, &l);
BACK;
ret += oldret;
}
if ((data)->minute)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->minute, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 5, &l);
BACK;
ret += oldret;
}
if ((data)->hour)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->hour, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 4, &l);
BACK;
ret += oldret;
}
if ((data)->day)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->day, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 3, &l);
BACK;
ret += oldret;
}
if ((data)->weekday)
{
int oldret = ret;
ret = 0;
e = enc_ROBIN_WEEKDAY(p, len, (data)->weekday, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 2, &l);
BACK;
ret += oldret;
}
if ((data)->month)
{
int oldret = ret;
ret = 0;
e = enc_ROBIN_MONTH(p, len, (data)->month, &l);
BACK;
e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_CONTEXT, CONS, 1, &l);
BACK;
ret += oldret;
}
if ((data)->year)
{
int oldret = ret;
ret = 0;
e = enc_int32(p, len, (data)->year, &l);
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
dec_RobinDateSpec(const unsigned char *p, size_t len, RobinDateSpec *data, size_t *size)
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
(data)->year = NULL;
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
(data)->year = malloc(sizeof(*(data)->year));
if ((data)->year == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->year, &l);
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
(data)->month = NULL;
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
(data)->month = malloc(sizeof(*(data)->month));
if ((data)->month == NULL) return ENOMEM;
e = dec_ROBIN_MONTH(p, len, (data)->month, &l);
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
(data)->weekday = NULL;
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
(data)->weekday = malloc(sizeof(*(data)->weekday));
if ((data)->weekday == NULL) return ENOMEM;
e = dec_ROBIN_WEEKDAY(p, len, (data)->weekday, &l);
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
(data)->day = NULL;
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
(data)->day = malloc(sizeof(*(data)->day));
if ((data)->day == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->day, &l);
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
(data)->hour = NULL;
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
(data)->hour = malloc(sizeof(*(data)->hour));
if ((data)->hour == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->hour, &l);
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
(data)->minute = NULL;
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
(data)->minute = malloc(sizeof(*(data)->minute));
if ((data)->minute == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->minute, &l);
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
(data)->second = NULL;
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
(data)->second = malloc(sizeof(*(data)->second));
if ((data)->second == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->second, &l);
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
(data)->nanosec = NULL;
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
(data)->nanosec = malloc(sizeof(*(data)->nanosec));
if ((data)->nanosec == NULL) return ENOMEM;
e = dec_int32(p, len, (data)->nanosec, &l);
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
free_RobinDateSpec(data);
return e;
}

void
free_RobinDateSpec(RobinDateSpec *data)
{
if ((data)->year) {
free((data)->year);
(data)->year = NULL;
}
if ((data)->month) {
free_ROBIN_MONTH((data)->month);
free((data)->month);
(data)->month = NULL;
}
if ((data)->weekday) {
free_ROBIN_WEEKDAY((data)->weekday);
free((data)->weekday);
(data)->weekday = NULL;
}
if ((data)->day) {
free((data)->day);
(data)->day = NULL;
}
if ((data)->hour) {
free((data)->hour);
(data)->hour = NULL;
}
if ((data)->minute) {
free((data)->minute);
(data)->minute = NULL;
}
if ((data)->second) {
free((data)->second);
(data)->second = NULL;
}
if ((data)->nanosec) {
free((data)->nanosec);
(data)->nanosec = NULL;
}
}

size_t
len_RobinDateSpec(const RobinDateSpec *data)
{
size_t ret = 0;
if((data)->year){
int oldret = ret;
ret = 0;
ret += len_int32((data)->year);
ret += 1 + len_len(ret) + oldret;
}
if((data)->month){
int oldret = ret;
ret = 0;
ret += len_ROBIN_MONTH((data)->month);
ret += 1 + len_len(ret) + oldret;
}
if((data)->weekday){
int oldret = ret;
ret = 0;
ret += len_ROBIN_WEEKDAY((data)->weekday);
ret += 1 + len_len(ret) + oldret;
}
if((data)->day){
int oldret = ret;
ret = 0;
ret += len_int32((data)->day);
ret += 1 + len_len(ret) + oldret;
}
if((data)->hour){
int oldret = ret;
ret = 0;
ret += len_int32((data)->hour);
ret += 1 + len_len(ret) + oldret;
}
if((data)->minute){
int oldret = ret;
ret = 0;
ret += len_int32((data)->minute);
ret += 1 + len_len(ret) + oldret;
}
if((data)->second){
int oldret = ret;
ret = 0;
ret += len_int32((data)->second);
ret += 1 + len_len(ret) + oldret;
}
if((data)->nanosec){
int oldret = ret;
ret = 0;
ret += len_int32((data)->nanosec);
ret += 1 + len_len(ret) + oldret;
}
ret += 1 + len_len(ret);
return ret;
}

int
copy_RobinDateSpec(const RobinDateSpec *from, RobinDateSpec *to)
{
if ((from)->year) {
(to)->year = malloc(sizeof(*(to)->year));
if ((to)->year == NULL) return ENOMEM;
*((to)->year) = *((from)->year);
} else
(to)->year = NULL;
if ((from)->month) {
(to)->month = malloc(sizeof(*(to)->month));
if ((to)->month == NULL) return ENOMEM;
if (copy_ROBIN_MONTH((from)->month, (to)->month)) return ENOMEM;
} else
(to)->month = NULL;
if ((from)->weekday) {
(to)->weekday = malloc(sizeof(*(to)->weekday));
if ((to)->weekday == NULL) return ENOMEM;
if (copy_ROBIN_WEEKDAY((from)->weekday, (to)->weekday)) return ENOMEM;
} else
(to)->weekday = NULL;
if ((from)->day) {
(to)->day = malloc(sizeof(*(to)->day));
if ((to)->day == NULL) return ENOMEM;
*((to)->day) = *((from)->day);
} else
(to)->day = NULL;
if ((from)->hour) {
(to)->hour = malloc(sizeof(*(to)->hour));
if ((to)->hour == NULL) return ENOMEM;
*((to)->hour) = *((from)->hour);
} else
(to)->hour = NULL;
if ((from)->minute) {
(to)->minute = malloc(sizeof(*(to)->minute));
if ((to)->minute == NULL) return ENOMEM;
*((to)->minute) = *((from)->minute);
} else
(to)->minute = NULL;
if ((from)->second) {
(to)->second = malloc(sizeof(*(to)->second));
if ((to)->second == NULL) return ENOMEM;
*((to)->second) = *((from)->second);
} else
(to)->second = NULL;
if ((from)->nanosec) {
(to)->nanosec = malloc(sizeof(*(to)->nanosec));
if ((to)->nanosec == NULL) return ENOMEM;
*((to)->nanosec) = *((from)->nanosec);
} else
(to)->nanosec = NULL;
return 0;
}

