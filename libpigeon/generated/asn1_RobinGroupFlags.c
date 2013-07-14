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
enc_RobinGroupFlags(unsigned char *p, size_t len, const RobinGroupFlags *data, size_t *size)
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
if (data->donthave) c |= 1<<5;
if (data->readonly) c |= 1<<6;
if (data->external) c |= 1<<7;
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
dec_RobinGroupFlags(const unsigned char *p, size_t len, RobinGroupFlags *data, size_t *size)
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
data->external = (*p >> 7) & 1;
data->readonly = (*p >> 6) & 1;
data->donthave = (*p >> 5) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinGroupFlags(data);
return e;
}

void
free_RobinGroupFlags(RobinGroupFlags *data)
{
}

size_t
len_RobinGroupFlags(const RobinGroupFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinGroupFlags(const RobinGroupFlags *from, RobinGroupFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinGroupFlags2int(RobinGroupFlags f)
{
unsigned r = 0;
if (f.external) r |= (1U << 0);
if (f.readonly) r |= (1U << 1);
if (f.donthave) r |= (1U << 2);
return r;
}

RobinGroupFlags int2RobinGroupFlags(unsigned n)
{
	RobinGroupFlags flags;

	flags.external = (n >> 0) & 1;
	flags.readonly = (n >> 1) & 1;
	flags.donthave = (n >> 2) & 1;
	return flags;
}

static tbunits RobinGroupFlags_units[] = {
	{"donthave",	1U << 2},
	{"readonly",	1U << 1},
	{"external",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinGroupFlags_units(void){
return RobinGroupFlags_units;
}

