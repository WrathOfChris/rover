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
enc_RobinSyncFlags(unsigned char *p, size_t len, const RobinSyncFlags *data, size_t *size)
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
if (data->additional) c |= 1<<7;
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
dec_RobinSyncFlags(const unsigned char *p, size_t len, RobinSyncFlags *data, size_t *size)
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
data->additional = (*p >> 7) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinSyncFlags(data);
return e;
}

void
free_RobinSyncFlags(RobinSyncFlags *data)
{
}

size_t
len_RobinSyncFlags(const RobinSyncFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinSyncFlags(const RobinSyncFlags *from, RobinSyncFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinSyncFlags2int(RobinSyncFlags f)
{
unsigned r = 0;
if (f.additional) r |= (1U << 0);
return r;
}

RobinSyncFlags int2RobinSyncFlags(unsigned n)
{
	RobinSyncFlags flags;

	flags.additional = (n >> 0) & 1;
	return flags;
}

static tbunits RobinSyncFlags_units[] = {
	{"additional",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinSyncFlags_units(void){
return RobinSyncFlags_units;
}

