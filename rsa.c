/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/03 19:09:32 by rpapagna          #+#    #+#             */
/*   Updated: 2019/12/05 18:17:57 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"
#include "cipher.h"

int				get_value(t_rsa *gg, __uint64_t value, int flag)
{
	if (!gg->n)
		gg->n = value;
	else if (!gg->e)
		gg->e = value;
	else if (!gg->d && !(flag))
		gg->d = value;
	else if (!gg->p && !(flag))
		gg->p = value;
	else if (!gg->q && !(flag))
		gg->q = value;
	else if (!gg->dmp1 && !(flag))
		gg->dmp1 = value;
	else if (!gg->dmq1 && !(flag))
		gg->dmq1 = value;
	else if (!gg->iqmp && !(flag))
		gg->iqmp = value;
	else
		return (0);
	return (1);
}

int				assign(uint8_t *decoded, t_rsa *gg, int decode_len, int flag)
{
	int			i;
	int			len;
	__uint64_t	value;

	i = 0;
	while (decoded[i] != 0x2)
		++i;
	while (i < decode_len)
	{
		len = 0;
		if (decoded[i++] == 0x2)
		{
			len = decoded[i];
			value = 0;
			while (len--)
			{
				if (value)
					value <<= 8;
				value += decoded[++i];
			}
			get_value(gg, value, flag);
		}
	}
	ft_memdel((void**)&decoded);
	return (i < decode_len ? 1 : 0);
}

int				validate_key(char *buf, t_rsa *gg, int flag)
{
	uint8_t		seq_decode[3];
	uint8_t		*decoded;
	int			n;
	float		decode_len;

	decode_len = 0;
	n = base64_decode((uint8_t *)buf, seq_decode, 4);
	decode_len = (((float)seq_decode[1] / 3.0) * 4.0);
	decoded = ft_memalloc((int)decode_len);
	n += base64_decode((uint8_t *)buf + n, decoded, (int)decode_len);
	if (buf[n + 1] != '-' && ft_pipewrench("-s", &decoded))
		return (0);
	if ((n <= 64 ? ((ft_strchri(buf, '-') - 1) % 4) :\
	((n + 1 != ft_strchri(buf, '-')) || ((n - (65 * (n / 64))) % 4))) &&\
		ft_error(flag ? 7 : 8, NULL, NULL) && ft_pipewrench("-s", &decoded))
		return ((buf[0] = 0));
	decode_len = (int)((decode_len / 4.0) * 3.0);
	if (assign(decoded, gg, (int)decode_len, flag))
		return (0);
	if (get_value(gg, 0, flag) && ft_error(flag ? 13 : 14, NULL, NULL))
		return ((buf[0] = 0));
	return (n <= 64 ? ft_strchri(buf, '-') : n + 1);
}

int				read_key(char *buf, t_rsa *gg, int flag, int fd)
{
	if (flag & R_CHECK && flag & R_PUBIN)
		return (ft_error(20, NULL, NULL));
	ft_bzero(buf, PAGESIZE);
	read(fd, buf, PAGESIZE);
	flag = flag & R_PUBIN ? 1 : 0;
	if (ft_strncmp(buf, flag ? PUB_BEG : PRIV_BEG, flag ? 27 : 32))
	{
		buf += ft_strchri(buf, '\n');
		buf += ft_strchri(buf, '-');
		if (ft_strncmp(buf, flag ? PUB_BEG : PRIV_BEG, flag ? 27 : 32) &&\
			ft_error(flag ? 9 : 10, NULL, NULL))
			return (ft_printf("%s", flag ? EXPECT_PUB : EXPECT_PRV));
	}
	buf += flag ? 27 : 32;
	if (!*buf)
		return (ft_error(flag ? 11 : 12, NULL, NULL));
	buf += validate_key(buf, gg, flag);
	if (!*buf)
		return (1);
	if (ft_strncmp(buf, flag ? PUB_END : PRIV_END, flag ? 25 : 30))
		return (ft_error(flag ? 11 : 12, NULL, NULL));
	return (0);
}

t_rsa			rsa_command(t_rsa_out rsa)
{
	t_rsa		gg;
	char		buf[PAGESIZE];
	__uint64_t	tmp;

	ft_bzero(&gg, sizeof(t_rsa));
	rsa.bits = 0;
	if ((rsa.flag & R_PUBIN && rsa.flag & R_DECRYPT && ft_error(19, NULL, NULL))
	|| read_key(buf, &gg, rsa.flag, rsa.type ? rsa.fd_inkey : rsa.fd_in))
		return (gg);
	tmp = gg.n;
	while (tmp && ++rsa.bits)
		tmp >>= 1;
	if (!rsa.type && rsa.flag & R_TEXT)
		rsa_text_out(rsa, gg);
	if (rsa.flag & R_MODULUS)
	{
		ft_bzero(buf, PAGESIZE);
		ft_sprintf(buf, "Modulus=%llX\n", gg.n);
		ft_putstr_fd(buf, rsa.fd_out);
	}
	if (rsa.flag & R_CHECK)
		rsa_out_options(rsa, gg, 'c');
	if (!rsa.type && !(rsa.flag & R_NOOUT))
		rsa_out_options(rsa, gg, 'o');
	return (gg);
}
