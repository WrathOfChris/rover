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
enc_ROBIN_LOCKTYPE(unsigned char *p, size_t len, const ROBIN_LOCKTYPE *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
{
unsigned char c = 0;
*p-- = c; len--; ret++;
c = 0;
*p-- = c; len--; ret++;
c = 0;
if (data->lock_break) c |= 1<<5;
if (data->lock_avail) c |= 1<<6;
if (data->lock_range) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
if (data->lock_whole) c |= 1<<0;
if (data->lock_lease) c |= 1<<1;
if (data->lock_ex) c |= 1<<2;
if (data->lock_pw) c |= 1<<3;
if (data->lock_pr) c |= 1<<4;
if (data->lock_cw) c |= 1<<5;
if (data->lock_cr) c |= 1<<6;
if (data->lock_nl) c |= 1<<7;
*p-- = c;
*p-- = 0;
len -= 2;
ret += 2;
}

e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_UNIV, PRIM,UT_BitString, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_LOCKTYPE(const unsigned char *p, size_t len, ROBIN_LOCKTYPE *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_UNIV, PRIM, UT_BitString, &reallen, &l);
FORW;
if (len < reallen)
	return TBASN1_OVERRUN;
p++;
len--;
reallen--;
ret++;
data->lock_nl = (*p >> 7) & 1;
data->lock_cr = (*p >> 6) & 1;
data->lock_cw = (*p >> 5) & 1;
data->lock_pr = (*p >> 4) & 1;
data->lock_pw = (*p >> 3) & 1;
data->lock_ex = (*p >> 2) & 1;
data->lock_lease = (*p >> 1) & 1;
data->lock_whole = (*p >> 0) & 1;
p++; len--; reallen--; ret++;
data->lock_range = (*p >> 7) & 1;
data->lock_avail = (*p >> 6) & 1;
data->lock_break = (*p >> 5) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_ROBIN_LOCKTYPE(data);
return e;
}

void
free_ROBIN_LOCKTYPE(ROBIN_LOCKTYPE *data)
{
}

size_t
len_ROBIN_LOCKTYPE(const ROBIN_LOCKTYPE *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_ROBIN_LOCKTYPE(const ROBIN_LOCKTYPE *from, ROBIN_LOCKTYPE *to)
{
*(to) = *(from);
return 0;
}

unsigned ROBIN_LOCKTYPE2int(ROBIN_LOCKTYPE f)
{
unsigned r = 0;
if (f.lock_nl) r |= (1U << 0);
if (f.lock_cr) r |= (1U << 1);
if (f.lock_cw) r |= (1U << 2);
if (f.lock_pr) r |= (1U << 3);
if (f.lock_pw) r |= (1U << 4);
if (f.lock_ex) r |= (1U << 5);
if (f.lock_lease) r |= (1U << 6);
if (f.lock_whole) r |= (1U << 7);
if (f.lock_range) r |= (1U << 8);
if (f.lock_avail) r |= (1U << 9);
if (f.lock_break) r |= (1U << 10);
return r;
}

ROBIN_LOCKTYPE int2ROBIN_LOCKTYPE(unsigned n)
{
	ROBIN_LOCKTYPE flags;

	flags.lock_nl = (n >> 0) & 1;
	flags.lock_cr = (n >> 1) & 1;
	flags.lock_cw = (n >> 2) & 1;
	flags.lock_pr = (n >> 3) & 1;
	flags.lock_pw = (n >> 4) & 1;
	flags.lock_ex = (n >> 5) & 1;
	flags.lock_lease = (n >> 6) & 1;
	flags.lock_whole = (n >> 7) & 1;
	flags.lock_range = (n >> 8) & 1;
	flags.lock_avail = (n >> 9) & 1;
	flags.lock_break = (n >> 10) & 1;
	return flags;
}

static tbunits ROBIN_LOCKTYPE_units[] = {
	{"lock_break",	1U << 10},
	{"lock_avail",	1U << 9},
	{"lock_range",	1U << 8},
	{"lock_whole",	1U << 7},
	{"lock_lease",	1U << 6},
	{"lock_ex",	1U << 5},
	{"lock_pw",	1U << 4},
	{"lock_pr",	1U << 3},
	{"lock_cw",	1U << 2},
	{"lock_cr",	1U << 1},
	{"lock_nl",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_ROBIN_LOCKTYPE_units(void){
return ROBIN_LOCKTYPE_units;
}

