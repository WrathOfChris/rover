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
enc_RobinTokens(unsigned char *p, size_t len, const RobinTokens *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
for (i = (data)->len - 1; i >= 0; --i) {
int oldret = ret;
ret = 0;
e = enc_RobinToken(p, len, &(data)->val[i], &l);
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
dec_RobinTokens(const unsigned char *p, size_t len, RobinTokens *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_UNIV, CONS, UT_Sequence, &reallen, &l);
FORW;
if (len < reallen)
return TBASN1_OVERRUN;
len = reallen;
{
size_t origlen = len;
int oldret = ret;
ret = 0;
(data)->len = 0;
(data)->val = NULL;
while (ret < origlen) {
(data)->len++;
(data)->val = realloc((data)->val, sizeof(*((data)->val)) * (data)->len);
e = dec_RobinToken(p, len, &(data)->val[(data)->len-1], &l);
FORW;
len = origlen - ret;
}
ret += oldret;
}
if (size) *size = ret;
return 0;
fail:
free_RobinTokens(data);
return e;
}

void
free_RobinTokens(RobinTokens *data)
{
while ((data)->len){
free_RobinToken(&(data)->val[(data)->len-1]);
(data)->len--;
}
free((data)->val);
(data)->val = NULL;
}

size_t
len_RobinTokens(const RobinTokens *data)
{
size_t ret = 0;
{
int oldret = ret;
int i;
ret = 0;
for (i = (data)->len - 1; i >= 0; --i){
int oldret = ret;
ret = 0;
ret += len_RobinToken(&(data)->val[i]);
ret += oldret;
}
ret += 1 + len_len(ret) + oldret;
}
return ret;
}

int
copy_RobinTokens(const RobinTokens *from, RobinTokens *to)
{
if (((to)->val = malloc((from)->len * sizeof(*(to)->val))) == NULL && (from)->len != 0)
return ENOMEM;
for ((to)->len = 0; (to)->len < (from)->len; (to)->len++){
if (copy_RobinToken(&(from)->val[(to)->len], &(to)->val[(to)->len])) return ENOMEM;
}
return 0;
}

RobinToken *
add_RobinToken(RobinTokens *data)
{
	RobinToken *this;
	if (!data) return NULL;
	if ((this = realloc(data->val, (data->len + 1) * sizeof(*data->val))) == NULL) return NULL;
	data->len++;
	data->val = this;
	bzero(&data->val[data->len - 1], sizeof(*data->val));
	return &data->val[data->len - 1];
}

int
del_RobinToken(RobinTokens *data, RobinToken *del)
{
	unsigned int u;
	RobinToken *this;
	if (!data) return TBOX_SUCCESS;
	if (data->len <= 0) return TBASN1_NOTFOUND;
	for (u = 0; u < data->len; u++) {
		if (&data->val[u] != del) continue;
		data->len--;
		if (data->len == 0) {
			free(data->val);
			data->val = NULL;
		} else {
			bcopy(&data->val[u + 1], &data->val[u], sizeof(*data->val) * (data->len - u));
			if ((this = realloc(data->val, data->len * sizeof(*data->val))) == NULL) return TBOX_SUCCESS;
			data->val = this;
		}
		return TBOX_SUCCESS;
	}
	return TBASN1_NOTFOUND;
}

