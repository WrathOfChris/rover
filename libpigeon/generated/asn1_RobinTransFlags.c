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
enc_RobinTransFlags(unsigned char *p, size_t len, const RobinTransFlags *data, size_t *size)
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
if (data->abort) c |= 1<<4;
if (data->readonly) c |= 1<<5;
if (data->append) c |= 1<<6;
if (data->resize) c |= 1<<7;
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
dec_RobinTransFlags(const unsigned char *p, size_t len, RobinTransFlags *data, size_t *size)
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
data->resize = (*p >> 7) & 1;
data->append = (*p >> 6) & 1;
data->readonly = (*p >> 5) & 1;
data->abort = (*p >> 4) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_RobinTransFlags(data);
return e;
}

void
free_RobinTransFlags(RobinTransFlags *data)
{
}

size_t
len_RobinTransFlags(const RobinTransFlags *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_RobinTransFlags(const RobinTransFlags *from, RobinTransFlags *to)
{
*(to) = *(from);
return 0;
}

unsigned RobinTransFlags2int(RobinTransFlags f)
{
unsigned r = 0;
if (f.resize) r |= (1U << 0);
if (f.append) r |= (1U << 1);
if (f.readonly) r |= (1U << 2);
if (f.abort) r |= (1U << 3);
return r;
}

RobinTransFlags int2RobinTransFlags(unsigned n)
{
	RobinTransFlags flags;

	flags.resize = (n >> 0) & 1;
	flags.append = (n >> 1) & 1;
	flags.readonly = (n >> 2) & 1;
	flags.abort = (n >> 3) & 1;
	return flags;
}

static tbunits RobinTransFlags_units[] = {
	{"abort",	1U << 3},
	{"readonly",	1U << 2},
	{"append",	1U << 1},
	{"resize",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_RobinTransFlags_units(void){
return RobinTransFlags_units;
}

