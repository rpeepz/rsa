/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   asn1_helper.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/16 17:48:28 by rpapagna          #+#    #+#             */
/*   Updated: 2019/11/17 21:03:27 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"
#include "cipher.h"

char		byte_len(__uint64_t n)
{
	char	len;

	len = 0;
	while (n)
	{
		len++;
		n >>= 8;
	}
	return (len);
}

uint8_t		*byte_string(uint8_t *buf, __uint64_t n)
{
	int		i;
	int		p;
	int		trig;

	i = -1;
	p = 0;
	trig = 0;
	ft_bzero(buf, 10);
	while (++i < 8)
	{
		if (trig || (n & (0xFFULL << 8 * (7 - i))) >> 8 * (7 - i))
		{
			buf[p] = (n & (0xFFULL << 8 * (7 - i))) >> 8 * (7 - i);
			DEBUG ? ft_printf("[%02x]", buf[p]) : 0;
			if (!trig && (buf[p] & 0x80))
			{
				buf[p + 1] = buf[p];
				buf[p++] = 0xFF;
			}
			p++;
			trig = 1;
		}
	}
	DEBUG ? ft_printf(" [%llu]\n", n) : 0;
	return (buf);
}

void		dump_to_buf(uint8_t *buf, char c, uint8_t *s, int *len)
{
	int		i;
	int		n;

	if (!s)
	{
		buf[*len] = c;
		++(*len);
	}
	else
	{
		i = 0;
		n = ft_strlen((char*)s);
		if (n == 1 && s[2] == '\x01')
			n = 3;
		DEBUG ? ft_printf("len:[%d] ", n) : 0;
		while (i < n || s[n])
		{
			DEBUG ? ft_printf("{%d}", i) : 0;
			buf[*len] = s[i];
			++(*len);
			++i;
		}
		DEBUG ? ft_printf(" ---\n") : 0;
	}
}
