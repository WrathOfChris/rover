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
enc_RobinRouterFlags(unsigned char *p, size_t len, const RobinRouterFlags *data, size_t *size)
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
if (data->softerror) c |= 1<<4;
if (data->harderror) c |= 1<<5;
if (data->offline) c |= 1<<6;
if (data->wipeme) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
if (data->master) c |= 1<<0;
if (data->fickle) c |= 1<<1;
if (data->readonly) c |= 1<<2;
if (data->deleted) c |= 1<<3;
if (data->valid) c |= 1<<4;
if (data->placeholder) c |= 1<<5;
if (data->inprogress) c |= 1<<6;
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
dec_RobinRouterFlags(const unsigned char *p, size_t len, RobinRouterFlags *data, size_t *size)
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
data->inprogress = (*p >> 6) & 1;
data->placeholder = (*p >> 5) & 1;
data->valid = (*p >> 4) & 1;
data->deleted = (*p >> 3) & 1;
data->readonly = (*p >> 2) & 1;
data->fickle = (*p >> 1) & 1;
data->master = (*p >> 0) & 1;
p++; len--; reallen--; ret++;
data->wipeme = (*p >> 7) & 1;
data->offline = (*p >> 6) & 1;
data->harderror = (*p >> 5) & 1;
data->softerror = (*p >> 4) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinRouterFlags(data);
return e;
}

void
free_RobinRouterFlags(RobinRouterFlags *data)
{
}

size_t
len_RobinRouterFlags(const RobinRouterFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinRouterFlags(const RobinRouterFlags *from, RobinRouterFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinRouterFlags2int(RobinRouterFlags f)
{
unsigned r = 0;
if (f.inprogress) r |= (1U << 1);
if (f.placeholder) r |= (1U << 2);
if (f.valid) r |= (1U << 3);
if (f.deleted) r |= (1U << 4);
if (f.readonly) r |= (1U << 5);
if (f.fickle) r |= (1U << 6);
if (f.master) r |= (1U << 7);
if (f.wipeme) r |= (1U << 8);
if (f.offline) r |= (1U << 9);
if (f.harderror) r |= (1U << 10);
if (f.softerror) r |= (1U << 11);
return r;
}

RobinRouterFlags int2RobinRouterFlags(unsigned n)
{
	RobinRouterFlags flags;

	flags.inprogress = (n >> 1) & 1;
	flags.placeholder = (n >> 2) & 1;
	flags.valid = (n >> 3) & 1;
	flags.deleted = (n >> 4) & 1;
	flags.readonly = (n >> 5) & 1;
	flags.fickle = (n >> 6) & 1;
	flags.master = (n >> 7) & 1;
	flags.wipeme = (n >> 8) & 1;
	flags.offline = (n >> 9) & 1;
	flags.harderror = (n >> 10) & 1;
	flags.softerror = (n >> 11) & 1;
	return flags;
}

static tbunits RobinRouterFlags_units[] = {
	{"softerror",	1U << 11},
	{"harderror",	1U << 10},
	{"offline",	1U << 9},
	{"wipeme",	1U << 8},
	{"master",	1U << 7},
	{"fickle",	1U << 6},
	{"readonly",	1U << 5},
	{"deleted",	1U << 4},
	{"valid",	1U << 3},
	{"placeholder",	1U << 2},
	{"inprogress",	1U << 1},
	{NULL,	0}
};

const tbunits * asn1_RobinRouterFlags_units(void){
return RobinRouterFlags_units;
}

