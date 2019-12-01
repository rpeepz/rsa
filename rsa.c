/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/03 19:09:32 by rpapagna          #+#    #+#             */
/*   Updated: 2019/11/17 21:02:21 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"
#include "encode.h"

int			assign(uint8_t *decoded, t_rsa *gg, int decode_len, int mode)
{
	int			i;

	i = 0;
	(void)gg;
	(void)mode;
	while (i < decode_len)
	{
		//decode key and save in gg
		ft_printf("[%x]", decoded[i]);
		i++;
	}
	ft_memdel((void**)&decoded);
	return (i < decode_len ? 1 : 0);
}

int				validate_key(char *buf, int flag, t_rsa *gg)
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
	decode_len = (int)((decode_len / 4.0) * 3.0);
	if (assign(decoded, gg, (int)decode_len, flag))
		return (0); //err: bad key
	return (n + 1); //success valid key
}

int				read_key(char *buf, int fd, int flag, t_rsa *gg)
{
	read(fd, buf, PAGESIZE);
	if (ft_strncmp(buf, flag & R_PUBIN ? PUB_BEG : PRIV_BEG,\
	flag & R_PUBIN ? 27 : 32))
	{
		ft_printf("%s, bad header\n", flag & R_PUBIN ? "expecting public key" :\
		"expecting private key");
		return (ft_error(0, 0, 0)); //return err: bad header
	}
	buf += flag & R_PUBIN ? 27 : 32;
	if (!*buf)
		return (ft_error(0, 0, 0)); //err input full key, not line by line
	buf += validate_key(buf, flag, gg);
	if (ft_strncmp(buf, flag & R_PUBIN ? PUB_END : PRIV_END,\
	flag & R_PUBIN ? 25 : 30))
		ft_printf("%s, bad header\n", flag & R_PUBIN ? "expecting public key" :\
		"expecting private key");
		return (ft_error(0, 0, 0)); //return err: bad header
	return (0);
}


void			rsa_command(t_rsa_out rsa)
{
	t_rsa		gg;
	char		buf[PAGESIZE];

	ft_bzero(&gg, sizeof(t_rsa));
	ft_bzero(buf, PAGESIZE);
	if (read_key(buf, rsa.fd_in, rsa.flag, &gg))
		ft_error(0, 0, 0); //err reading key
	else if (rsa.flag & R_NOOUT)
		return ;
	else if (rsa.flag & R_CHECK)
		;
	else if (rsa.flag & R_TEXT)
		;//decode(rsa, &gg, 1);
	else if (rsa.flag & R_PUBOUT)
		;//decode(rsa, &gg, 2);
	rsa_text_out(rsa, gg);
}
