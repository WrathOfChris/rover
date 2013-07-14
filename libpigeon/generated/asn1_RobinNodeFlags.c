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
enc_RobinNodeFlags(unsigned char *p, size_t len, const RobinNodeFlags *data, size_t *size)
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
*p-- = c; len--; ret++;
c = 0;
if (data->wipe) c |= 1<<5;
if (data->force) c |= 1<<6;
if (data->lock_attr) c |= 1<<7;
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
dec_RobinNodeFlags(const unsigned char *p, size_t len, RobinNodeFlags *data, size_t *size)
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
data->lock_attr = (*p >> 7) & 1;
data->force = (*p >> 6) & 1;
data->wipe = (*p >> 5) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinNodeFlags(data);
return e;
}

void
free_RobinNodeFlags(RobinNodeFlags *data)
{
}

size_t
len_RobinNodeFlags(const RobinNodeFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinNodeFlags(const RobinNodeFlags *from, RobinNodeFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinNodeFlags2int(RobinNodeFlags f)
{
unsigned r = 0;
if (f.lock_attr) r |= (1U << 0);
if (f.force) r |= (1U << 1);
if (f.wipe) r |= (1U << 2);
return r;
}

RobinNodeFlags int2RobinNodeFlags(unsigned n)
{
	RobinNodeFlags flags;

	flags.lock_attr = (n >> 0) & 1;
	flags.force = (n >> 1) & 1;
	flags.wipe = (n >> 2) & 1;
	return flags;
}

static tbunits RobinNodeFlags_units[] = {
	{"wipe",	1U << 2},
	{"force",	1U << 1},
	{"lock_attr",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinNodeFlags_units(void){
return RobinNodeFlags_units;
}

