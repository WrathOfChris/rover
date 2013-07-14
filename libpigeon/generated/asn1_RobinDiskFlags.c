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
enc_RobinDiskFlags(unsigned char *p, size_t len, const RobinDiskFlags *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
{
unsigned char c = 0;
if (data->local8) c |= 1<<0;
if (data->local7) c |= 1<<1;
if (data->local6) c |= 1<<2;
if (data->local5) c |= 1<<3;
if (data->local4) c |= 1<<4;
if (data->local3) c |= 1<<5;
if (data->local2) c |= 1<<6;
if (data->local1) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
*p-- = c; len--; ret++;
c = 0;
if (data->powersave) c |= 1<<5;
if (data->failure) c |= 1<<6;
if (data->repair) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
if (data->verify) c |= 1<<0;
if (data->compact) c |= 1<<1;
if (data->fickle) c |= 1<<2;
if (data->readonly) c |= 1<<3;
if (data->drain) c |= 1<<4;
if (data->down) c |= 1<<5;
if (data->up) c |= 1<<6;
if (data->available) c |= 1<<7;
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
dec_RobinDiskFlags(const unsigned char *p, size_t len, RobinDiskFlags *data, size_t *size)
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
data->available = (*p >> 7) & 1;
data->up = (*p >> 6) & 1;
data->down = (*p >> 5) & 1;
data->drain = (*p >> 4) & 1;
data->readonly = (*p >> 3) & 1;
data->fickle = (*p >> 2) & 1;
data->compact = (*p >> 1) & 1;
data->verify = (*p >> 0) & 1;
p++; len--; reallen--; ret++;
data->repair = (*p >> 7) & 1;
data->failure = (*p >> 6) & 1;
data->powersave = (*p >> 5) & 1;
p++; len--; reallen--; ret++;
p++; len--; reallen--; ret++;
data->local1 = (*p >> 7) & 1;
data->local2 = (*p >> 6) & 1;
data->local3 = (*p >> 5) & 1;
data->local4 = (*p >> 4) & 1;
data->local5 = (*p >> 3) & 1;
data->local6 = (*p >> 2) & 1;
data->local7 = (*p >> 1) & 1;
data->local8 = (*p >> 0) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinDiskFlags(data);
return e;
}

void
free_RobinDiskFlags(RobinDiskFlags *data)
{
}

size_t
len_RobinDiskFlags(const RobinDiskFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinDiskFlags(const RobinDiskFlags *from, RobinDiskFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinDiskFlags2int(RobinDiskFlags f)
{
unsigned r = 0;
if (f.available) r |= (1U << 0);
if (f.up) r |= (1U << 1);
if (f.down) r |= (1U << 2);
if (f.drain) r |= (1U << 3);
if (f.readonly) r |= (1U << 4);
if (f.fickle) r |= (1U << 5);
if (f.compact) r |= (1U << 6);
if (f.verify) r |= (1U << 7);
if (f.repair) r |= (1U << 8);
if (f.failure) r |= (1U << 9);
if (f.powersave) r |= (1U << 10);
if (f.local1) r |= (1U << 24);
if (f.local2) r |= (1U << 25);
if (f.local3) r |= (1U << 26);
if (f.local4) r |= (1U << 27);
if (f.local5) r |= (1U << 28);
if (f.local6) r |= (1U << 29);
if (f.local7) r |= (1U << 30);
if (f.local8) r |= (1U << 31);
return r;
}

RobinDiskFlags int2RobinDiskFlags(unsigned n)
{
	RobinDiskFlags flags;

	flags.available = (n >> 0) & 1;
	flags.up = (n >> 1) & 1;
	flags.down = (n >> 2) & 1;
	flags.drain = (n >> 3) & 1;
	flags.readonly = (n >> 4) & 1;
	flags.fickle = (n >> 5) & 1;
	flags.compact = (n >> 6) & 1;
	flags.verify = (n >> 7) & 1;
	flags.repair = (n >> 8) & 1;
	flags.failure = (n >> 9) & 1;
	flags.powersave = (n >> 10) & 1;
	flags.local1 = (n >> 24) & 1;
	flags.local2 = (n >> 25) & 1;
	flags.local3 = (n >> 26) & 1;
	flags.local4 = (n >> 27) & 1;
	flags.local5 = (n >> 28) & 1;
	flags.local6 = (n >> 29) & 1;
	flags.local7 = (n >> 30) & 1;
	flags.local8 = (n >> 31) & 1;
	return flags;
}

static tbunits RobinDiskFlags_units[] = {
	{"local8",	1U << 31},
	{"local7",	1U << 30},
	{"local6",	1U << 29},
	{"local5",	1U << 28},
	{"local4",	1U << 27},
	{"local3",	1U << 26},
	{"local2",	1U << 25},
	{"local1",	1U << 24},
	{"powersave",	1U << 10},
	{"failure",	1U << 9},
	{"repair",	1U << 8},
	{"verify",	1U << 7},
	{"compact",	1U << 6},
	{"fickle",	1U << 5},
	{"readonly",	1U << 4},
	{"drain",	1U << 3},
	{"down",	1U << 2},
	{"up",	1U << 1},
	{"available",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinDiskFlags_units(void){
return RobinDiskFlags_units;
}

