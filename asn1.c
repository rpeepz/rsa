/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   asn1.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/16 17:48:28 by rpapagna          #+#    #+#             */
/*   Updated: 2019/11/17 21:03:27 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"
#include "encode.h"

static void		asn1_cont(t_rsa gg, uint8_t *buf, uint8_t *buf2, int *len)
{
	uint8_t		copy[PAGESIZE];
	int			index;

	dump_to_buf(buf, byte_string(buf2, gg.dmp1)[0] == 0xFF ?
	byte_len(gg.dmp1) + 1 : byte_len(gg.dmp1), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.dmp1), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.dmq1)[0] == 0xFF ?
	byte_len(gg.dmq1) + 1 : byte_len(gg.dmq1), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.dmq1), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.iqmp)[0] == 0xFF ?
	byte_len(gg.iqmp) + 1 : byte_len(gg.iqmp), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.iqmp), len);
	ft_memcpy(copy, buf, *len);
	ft_bzero(buf, PAGESIZE);
	index = 0;
	dump_to_buf(buf, SEQUENCE, NULL, &index);
	dump_to_buf(buf, (char)(*len + 3), NULL, &index);
	dump_to_buf(buf, INT, NULL, &index);
	dump_to_buf(buf, V, NULL, &index);
	dump_to_buf(buf, V1, NULL, &index);
	ft_memcpy(&buf[index], copy, *len);
	*len += 5;
}

void			asn1(t_rsa gg, uint8_t *buf, uint8_t *buf2, int *len)
{
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.n)[0] == 0xFF ?
	byte_len(gg.n) + 1 : byte_len(gg.n), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.n), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_len(gg.e), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.e), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.d)[0] == 0xFF ?
	byte_len(gg.d) + 1 : byte_len(gg.d), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.d), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.p)[0] == 0xFF ?
	byte_len(gg.p) + 1 : byte_len(gg.p), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.p), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.q)[0] == 0xFF ?
	byte_len(gg.q) + 1 : byte_len(gg.q), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.q), len);
	dump_to_buf(buf, INT, NULL, len);
	asn1_cont(gg, buf, buf2, len);
}

void			asn1_pub(t_rsa gg, uint8_t *buf, uint8_t *buf2, int *len)
{
	uint8_t		copy[PAGESIZE];
	int			index;

	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_string(buf2, gg.n)[0] == 0xFF ?
	byte_len(gg.n) + 1 : byte_len(gg.n), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.n), len);
	dump_to_buf(buf, INT, NULL, len);
	dump_to_buf(buf, byte_len(gg.e), NULL, len);
	dump_to_buf(buf, 0, byte_string(buf2, gg.e), len);
	ft_memcpy(copy, buf, *len);
	ft_bzero(buf, PAGESIZE);
	index = 2;
	dump_to_buf(buf, SEQUENCE, NULL, &index);
	dump_to_buf(buf, 0, (uint8_t*)PKCS_1, &index);
	dump_to_buf(buf, BIT, NULL, &index);
	dump_to_buf(buf, (char)(*len) + 3, NULL, &index);
	dump_to_buf(buf, V1, NULL, &index);
	dump_to_buf(buf, SEQUENCE, NULL, &index);
	dump_to_buf(buf, (char)(*len), NULL, &index);
	ft_memcpy(&buf[index], copy, *len);
	*len += index;
	buf[0] = SEQUENCE;
	buf[1] = (uint8_t)*len - 2;
}
