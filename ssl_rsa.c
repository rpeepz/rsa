/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl_rsa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/12 18:59:43 by rpapagna          #+#    #+#             */
/*   Updated: 2019/11/04 20:54:31 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"

int				check_utl_arg(t_rsa_out *rsa, char *arg)
{
	if (!ft_strcmp(arg, "pubin"))
		rsa->flag |= 0x8;
	else if (!ft_strcmp(arg, "encrypt"))
		rsa->flag |= 0x10;
	else if (!ft_strcmp(arg, "decrypt"))
		rsa->flag |= 0x20;
	else if (!ft_strcmp(arg, "hexdump"))
		rsa->flag |= 0x40;
	else
		return (1);
	return (0);
}

int				check_rsa_arg(t_rsa_out *rsa, char *arg)
{
	if (!ft_strcmp(arg, "text"))
		rsa->flag |= R_TEXT;
	else if (!ft_strcmp(arg, "noout"))
		rsa->flag |= R_NOOUT;
	else if (!ft_strcmp(arg, "check"))
		rsa->flag |= R_CHECK;
	else if (!ft_strcmp(arg, "pubin"))
		rsa->flag |= R_PUBIN;
	else if (!ft_strcmp(arg, "pubout"))
		rsa->flag |= R_PUBOUT;
	else if (!ft_strcmp(arg, "modulus"))
		rsa->flag |= R_MODULUS;
	else
		return (1);
	return (0);
}

int				valid_arg(t_ssl *ssl, t_rsa_out *rsa, char *arg, char *fname)
{
	if ((rsa->fd_out == 1) && !ft_strcmp(arg, "out"))
	{
		rsa->flag |= F_OUT;
		return (!fname ? 1 : 0);
	}
	else if (ssl->type == 31)
		return (1);
	else if (!ft_strcmp(arg, "in"))
	{
		rsa->flag |= F_IN;
		return ((!fname || open_file_to_fd(&ssl->fd[254], fname, 0)) ? 1 : 0);
	}
	else if (ssl->type == 32)
	{
		if (!ft_strcmp(arg, "inkey"))
		{
			rsa->flag |= F_INK;
			return ((!fname || open_file_to_fd(&ssl->fd[254], fname, 0)) ?\
			1 : 0);
		}
		return (check_utl_arg(rsa, arg));
	}
	else if (ssl->type == 33)
		return (check_rsa_arg(rsa, arg));
	return (0);
}

int				parse_rsa(char **av, t_ssl *ssl, t_rsa_out *rsa, int i)
{
	while ((av[++i]))
	{
		if ((ssl->type == 31 || ssl->type == 36) && ft_isdigit(av[i][0]))
		{
			if ((rsa->bits = ft_atoi(av[i])) > MAX_BIT_KEY)
				rsa->bits = MAX_BIT_KEY;
			else if (ssl->type == 31 && rsa->bits < 16)
				return ((rsa->bits = -1));
			break ;
		}
		if (av[i][0] == '-')
		{
			if (valid_arg(ssl, rsa, &av[i][1], av[i + 1]))
				return (ft_error(6, &av[i][1], ssl));
			else if (rsa->fd_out == 1 && rsa->flag & 0x1)
				open_file_to_fd(&rsa->fd_out, av[++i], 1);
			else if (ssl->type > 31 && (!rsa->fd_in) && (rsa->flag & F_IN))
				open_file_to_fd(&rsa->fd_in, av[++i], 0);
			else if (ssl->type == 32 && (!rsa->fd_inkey) && (rsa->flag & F_INK))
				open_file_to_fd(&rsa->fd_inkey, av[++i], 0);
		}
		else
			return (ft_error(6, av[i], ssl));
	}
	return (0);
}

void			ssl_rsa(char **av, t_ssl *ssl)
{
	t_rsa_out	rsa;

	ft_bzero(&rsa, sizeof(t_rsa_out));
	rsa.fd_out = 1;
	rsa.bits = MAX_BIT_KEY;
	if (parse_rsa(av, ssl, &rsa, 1))
	{
		if (rsa.bits == -1)
			ft_printf("rsa routines:RSA_BUILTIN_KEYGEN:key size too small\n");
		else
			return ;
	}
	if (ssl->type == 31 && rsa.bits > 15)
		genrsa(rsa);
	else if (!av[2] && ssl->type != 33 && (ssl->flag = 'Z'))
		ft_error(6, av[1], ssl);
	else if (ssl->type == 32)
		;//rsa_util(rsa);
	else if (ssl->type == 33)
		rsa_command(rsa);
	else if (ssl->type == 36)
		ft_is_primary(ft_atoull(av[2]), 9.0F) ?
		ft_printf("%llu is prime.\n", ft_atoull(av[2])) :
		ft_printf("%llu is composite.\n", ft_atoull(av[2]));
	DEBUG ? debug_output(ssl, rsa) : 0;
}
