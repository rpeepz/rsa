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

void				decode(t_rsa_out rsa, t_rsa *gg, int mode)
{
	(void)rsa;
	(void)gg;
	(void)mode;
}

int				validate_key(char *buf, int flag)
{
	(void)buf;
	(void)flag;
	//decode ?
	return (0); //success on valid line of key
	return (1); //err: expecting public or private key
}

int				read_key(char *buf, int fd, int flag)
{
	int		ret;
	
	read(fd, buf, flag & R_PUBIN ? 27 : 32);
	if (ft_strcmp(buf, flag & R_PUBIN ? PUB_BEG : PRIV_BEG))
		ft_printf("err\n");
		ft_error(0, 0, 0); //return err: bad header
	ft_bzero(buf, 65);
	while ((ret = read(fd, buf, 65) > 0))
	{
		ft_printf("[%s]\n", buf);
		validate_key(buf, flag);
		ft_bzero(buf, 65);
	}
	ft_bzero(buf, 65);
	read(fd, buf, flag & R_PUBIN ? 25 : 30);
	if (ft_strcmp(buf, flag & R_PUBIN ? PUB_END : PRIV_END))
		ft_printf("err\n");
		ft_error(0, 0, 0); //return err: bad header
	return (0);
}


void				rsa_command(t_rsa_out rsa)
{
	t_rsa		gg;
	char		buf[65];

	ft_bzero(&gg, sizeof(t_rsa));
	ft_bzero(buf, 65);
	if (read_key(buf, rsa.fd_in, rsa.flag))
		ft_error(0, 0, 0); //err reading key
	else if (rsa.flag & R_NOOUT)
		return ;
	else if (rsa.flag & R_CHECK)
		;
	else if (rsa.flag & R_TEXT)
		decode(rsa, &gg, 1);
	else if (rsa.flag & R_PUBOUT)
		decode(rsa, &gg, 2);
	rsa_text_out(rsa, gg);
}
