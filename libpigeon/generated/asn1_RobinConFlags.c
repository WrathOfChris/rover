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
enc_RobinConFlags(unsigned char *p, size_t len, const RobinConFlags *data, size_t *size)
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
if (data->graceful) c |= 1<<3;
if (data->shutdown) c |= 1<<4;
if (data->compress) c |= 1<<5;
if (data->noencrypt) c |= 1<<6;
if (data->nosign) c |= 1<<7;
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
dec_RobinConFlags(const unsigned char *p, size_t len, RobinConFlags *data, size_t *size)
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
data->nosign = (*p >> 7) & 1;
data->noencrypt = (*p >> 6) & 1;
data->compress = (*p >> 5) & 1;
data->shutdown = (*p >> 4) & 1;
data->graceful = (*p >> 3) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinConFlags(data);
return e;
}

void
free_RobinConFlags(RobinConFlags *data)
{
}

size_t
len_RobinConFlags(const RobinConFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinConFlags(const RobinConFlags *from, RobinConFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinConFlags2int(RobinConFlags f)
{
unsigned r = 0;
if (f.nosign) r |= (1U << 0);
if (f.noencrypt) r |= (1U << 1);
if (f.compress) r |= (1U << 2);
if (f.shutdown) r |= (1U << 3);
if (f.graceful) r |= (1U << 4);
return r;
}

RobinConFlags int2RobinConFlags(unsigned n)
{
	RobinConFlags flags;

	flags.nosign = (n >> 0) & 1;
	flags.noencrypt = (n >> 1) & 1;
	flags.compress = (n >> 2) & 1;
	flags.shutdown = (n >> 3) & 1;
	flags.graceful = (n >> 4) & 1;
	return flags;
}

static tbunits RobinConFlags_units[] = {
	{"graceful",	1U << 4},
	{"shutdown",	1U << 3},
	{"compress",	1U << 2},
	{"noencrypt",	1U << 1},
	{"nosign",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinConFlags_units(void){
return RobinConFlags_units;
}

