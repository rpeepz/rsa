/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsautl.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/04 13:21:29 by rpapagna          #+#    #+#             */
/*   Updated: 2019/12/06 21:41:41 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"

void			print_row_hex(int bytes, int len, __uint8_t *msg, int fd)
{
	char	*hex;
	int		i;

	hex = "0123456789abcdef";
	i = 0;
	if (bytes < 16)
		ft_putstr_fd("0000 - ", fd);
	while (i < 16)
	{
		if (i < len)
		{
			ft_putchar_fd(hex[(msg[i] / 16)], fd);
			ft_putchar_fd(hex[(msg[i] % 16)], fd);
		}
		else
			ft_putstr_fd("  ", fd);
		++i;
		if (i % 8 == 0)
			ft_putchar_fd(i == 8 ? '-' : ' ', fd);
		ft_putchar_fd(' ', fd);
	}
}

static void		hex_dump(int fd, int size, int len, __uint64_t msg)
{
	__uint8_t	s[len];
	int			i;
	int			j;

	i = 0;
	s[len] = 0;
	while (i < len)
	{
		s[i] = (char)(msg >> (size - (i * 8)));
		++i;
	}
	i = 0;
	while (i < len)
	{
		print_row_hex(i, len - i, s + i, fd);
		j = 0;
		while (j < 16 && j < len - i)
		{
			ft_putchar_fd(ft_isprint(s[i + j]) ? s[i + j] : '.', fd);
			j++;
		}
		ft_putchar_fd('\n', fd);
		i += 16;
	}
}

static void		rsa_crypt(t_rsa_out rsa, t_rsa gg, __uint8_t *buf, int len)
{
	__uint64_t	msg;
	int			size;
	int			i;

	i = 0;
	msg = 0;
	while (i < len)
	{
		msg <<= 8;
		msg += buf[i++];
	}
	msg = powmod(msg, rsa.flag & R_DECRYPT ? gg.d : gg.e, gg.n);
	i = 0;
	size = (len * 8) - 8;
	if (rsa.flag & R_HEXDUMP)
		hex_dump(rsa.fd_out, size, len, msg);
	else
	{
		while (i < len)
		{
			ft_putchar_fd((char)(msg >> (size - (i * 8))), rsa.fd_out);
			++i;
		}
	}
}

void			rsautl(t_rsa_out rsa, t_rsa gg)
{
	__uint64_t		tmp;
	int				len;
	__uint8_t		buf[16];

	if (!gg.n)
		return ;
	rsa.bits = 0;
	ft_bzero(buf, 16);
	tmp = gg.n;
	while (tmp && ++rsa.bits)
		tmp >>= 1;
	len = read(rsa.fd_in, buf, 15);
	if (rsa.bits >> 3 != len)
		ft_error(len < rsa.bits >> 3 ? 21 : 22, NULL, NULL);
	else
		rsa_crypt(rsa, gg, buf, len);
}
