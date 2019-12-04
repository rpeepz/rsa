/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsautl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/04 13:21:29 by rpapagna          #+#    #+#             */
/*   Updated: 2019/11/17 21:03:49 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"

void			rsa_decrypt(t_rsa_out rsa, t_rsa gg, char *buf, int len)
{
	__uint64_t	decrypt[len];
	int			i;

	for (i = 0; i < len; i++) { 
		ft_printf("%c", buf[i]);
	}
	ft_printf("\n");
	i = 0;
	while (i < len)
	{
		decrypt[i] = powmod(buf[i], gg.d, gg.n);
		++i;
	}
	for (i = 0; i < len; i++) { 
		ft_printf("%c", decrypt[i]);
	}
}

void			rsa_encrypt(t_rsa_out rsa, t_rsa gg, char *buf, int len)
{
	__uint64_t	encrypt;
	int			i;

	for (i = 0; i < len; i++) { 
		ft_printf("%c", buf[i]);
	}
	ft_printf("\n");
	i = 0;
	encrypt = 0;
	while (i < len)
	{
		encrypt <<= 8;
		encrypt += buf[i];
		++i;
	}
	encrypt = powmod(encrypt, gg.e, gg.n);
	for (i = 0; i < len; i++) {
		char cha = encrypt >> (56 - (i * 8));
		ft_printf("%c", cha);
	}
	ft_printf("\n");
}

void			rsautl(t_rsa_out rsa, t_rsa gg)
{
	__uint64_t		tmp;
	int				len;
	char			buf[16];

	rsa.bits = 0;
	ft_bzero(buf, 16);
	tmp = gg.n;
	while (tmp && ++rsa.bits)
		tmp >>= 1;
	len = read(rsa.fd_in, buf, 15);
	if (rsa.bits >> 3 != len)
		ft_error(len < rsa.bits >> 3 ? 21 : 22, NULL, NULL);
	else
	{
		if (rsa.flag & R_DECRYPT)
			rsa_decrypt(rsa, gg, buf, len);
		else if (rsa.flag & R_ENCRYPT)
			rsa_encrypt(rsa, gg, buf, len);
	}

}
