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
enc_RobinGroupRight(unsigned char *p, size_t len, const RobinGroupRight *data, size_t *size)
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
if (data->delete) c |= 1<<3;
if (data->insert) c |= 1<<4;
if (data->membership) c |= 1<<5;
if (data->ownership) c |= 1<<6;
if (data->display) c |= 1<<7;
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
dec_RobinGroupRight(const unsigned char *p, size_t len, RobinGroupRight *data, size_t *size)
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
data->display = (*p >> 7) & 1;
data->ownership = (*p >> 6) & 1;
data->membership = (*p >> 5) & 1;
data->insert = (*p >> 4) & 1;
data->delete = (*p >> 3) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinGroupRight(data);
return e;
}

void
free_RobinGroupRight(RobinGroupRight *data)
{
}

size_t
len_RobinGroupRight(const RobinGroupRight *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinGroupRight(const RobinGroupRight *from, RobinGroupRight *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinGroupRight2int(RobinGroupRight f)
{
unsigned r = 0;
if (f.display) r |= (1U << 0);
if (f.ownership) r |= (1U << 1);
if (f.membership) r |= (1U << 2);
if (f.insert) r |= (1U << 3);
if (f.delete) r |= (1U << 4);
return r;
}

RobinGroupRight int2RobinGroupRight(unsigned n)
{
	RobinGroupRight flags;

	flags.display = (n >> 0) & 1;
	flags.ownership = (n >> 1) & 1;
	flags.membership = (n >> 2) & 1;
	flags.insert = (n >> 3) & 1;
	flags.delete = (n >> 4) & 1;
	return flags;
}

static tbunits RobinGroupRight_units[] = {
	{"delete",	1U << 4},
	{"insert",	1U << 3},
	{"membership",	1U << 2},
	{"ownership",	1U << 1},
	{"display",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinGroupRight_units(void){
return RobinGroupRight_units;
}

