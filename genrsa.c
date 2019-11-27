/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   genrsa.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/31 22:56:10 by rpapagna          #+#    #+#             */
/*   Updated: 2019/11/17 21:06:55 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"

__uint64_t		genrand(__uint64_t min, __uint64_t max)
{
	int				fd;
	int				bytes;
	__uint64_t		tmp;
	unsigned char	*buf;

	tmp = max;
	bytes = 0;
	while (tmp && ++bytes)
		tmp >>= 8;
	buf = ft_memalloc(sizeof(unsigned char) * (bytes + 1));
	fd = open("/dev/urandom", O_RDONLY);
	while (1)
	{
		ft_bzero(buf, bytes);
		read(fd, buf, bytes);
		ft_memcpy(&tmp, buf, bytes);
		if (tmp >= min && tmp <= max)
			break ;
	}
	close(fd);
	free(buf);
	return (tmp);
}

__uint64_t		genprime(int bits, int out)
{
	__uint64_t			p;
	__uint64_t			min;
	__uint64_t			max;
	unsigned int		i;

	min = 1ULL << (abs(bits - 1));
	max = (1ULL << bits) - 1;
	i = 0;
	while (1)
	{
		if (i % (bits * 2) == 0)
		{
			p = genrand(min, max) | 1;
			p |= 1ULL << (bits - 1);
			out ? 0 : ft_putchar_fd('.', 2);
		}
		if (ft_is_primary(p, out))
			break ;
		out ? 0 : ft_putchar_fd('.', 2);
		p -= 2;
		i++;
	}
	DEBUG ? ft_printf("\nSUCCESS\tprime --> [%llb]", p) : 0;
	out ? 0 : ft_putchar_fd('\n', 2);
	return (p);
}

__uint64_t		valid_modulus(t_rsa gg, int bits)
{
	__uint64_t	n;

	n = gg.p * gg.q;
	if ((n / gg.p == gg.q) && n & 1ULL << (bits - 1))
		return (n);
	return (1);
}

/*
**	primes with errors
**	gg.p = 61871;
**	gg.q = 47279;
**	gg.p = 3620177833;
**	gg.q = 2455139927;
**	gg.p = 2366981909;
**	gg.q = 7162022459;
*/

__uint64_t		genrsa(t_rsa_out rsa)
{
	t_rsa		gg;
	char		buf[80];

	ft_bzero(buf, 80);
	ft_sprintf(buf, "Generating RSA private key, %d bit long modulus\n",
	rsa.bits);
	ft_putstr_fd(buf, 2);
	while (1)
	{
		gg.p = genprime((rsa.bits / 2), (int)gg.n);
		gg.q = genprime((rsa.bits / 2) + 1, (int)gg.n);
		if ((gg.n = valid_modulus(gg, rsa.bits)) != 1)
			break ;
	}
	gg.e = 65537;
	gg.phi = (gg.p - 1) * (gg.q - 1);
	gg.d = mod_inverse(gg.e, gg.phi);
	gg.dmp1 = gg.d % (gg.p - 1);
	gg.dmq1 = gg.d % (gg.q - 1);
	gg.iqmp = mod_inverse(gg.q, gg.p);
	ft_bzero(buf, 80);
	ft_sprintf(buf, "e is %llu (%#x)\n", gg.e, gg.e);
	ft_putstr_fd(buf, 2);
	rsa_encode_out(rsa, gg);
	return (gg.n);
}