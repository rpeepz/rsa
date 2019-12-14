/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rsa_out.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rpapagna <rpapagna@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/03 18:41:24 by rpapagna          #+#    #+#             */
/*   Updated: 2019/12/14 01:29:19 by rpapagna         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "rsa.h"
#include "encode.h"

void			debug_output(t_ssl *ssl, t_rsa_out rsa)
{
	ft_printf("ssl flags  [%b]\n", ssl->flag);
	ft_printf("ssl type   [%d]\n", ssl->type);
	ft_printf("rsa bits   [%d]\n", rsa.bits);
	ft_printf("rsa fd in  [%d]\n", rsa.fd_in);
	ft_printf("rsa fd out [%d]\n", rsa.fd_out);
	ft_printf("rsa in key [%d]\n", rsa.fd_inkey);
	ft_printf("rsa flags  [%b]\n", rsa.flag);
	ft_printf("rsa type   [%d]\n", rsa.type);
}

void			rsa_text_out(t_rsa_out rsa, t_rsa gg)
{
	char	buf[PAGESIZE];

	ft_bzero(buf, PAGESIZE);
	ft_sprintf(buf, "%s-Key: (%d bit)\n",
	rsa.flag & R_PUBIN ? "Public" : "Private", rsa.bits);
	ft_sprintf(&buf[ft_strlen(buf)], "%codulus: %llu (%#llx)\n",\
	rsa.flag & R_PUBIN ? 'M' : 'm', gg.n, gg.n);
	ft_sprintf(&buf[ft_strlen(buf)], "%sxponent: %llu (%#llx)\n",
	rsa.flag & R_PUBIN ? "E" : "publicE", gg.e, gg.e);
	if (!(rsa.flag & R_PUBIN))
	{
		ft_sprintf(&buf[ft_strlen(buf)],
		"privateExponent: %llu (%#llx)\n", gg.d, gg.d);
		ft_sprintf(&buf[ft_strlen(buf)], "prime1: %llu (%#llx)\n", gg.p, gg.p);
		ft_sprintf(&buf[ft_strlen(buf)], "prime2: %llu (%#llx)\n", gg.q, gg.q);
		ft_sprintf(&buf[ft_strlen(buf)],
		"exponent1: %llu (%#llx)\n", gg.dmp1, gg.dmp1);
		ft_sprintf(&buf[ft_strlen(buf)],
		"exponent2: %llu (%#llx)\n", gg.dmq1, gg.dmq1);
		ft_sprintf(&buf[ft_strlen(buf)],
		"coefficient: %llu (%#llx)\n", gg.iqmp, gg.iqmp);
	}
	ft_putstr_fd(buf, rsa.fd_out);
}

void			rsa_encode_out(t_rsa_out rsa, t_rsa gg)
{
	int			len;
	int			i;
	uint8_t		buf[PAGESIZE];
	uint8_t		buf2[10];

	ft_bzero(buf, PAGESIZE);
	ft_bzero(buf2, 10);
	len = 0;
	(rsa.flag & R_PUBOUT || rsa.flag & R_PUBIN) ?\
	asn1_pub(gg, buf, buf2, &len) : asn1(gg, buf, buf2, &len);
	DEBUG ? ft_printf("asn1 len:[%d]\n", len) : 0;
	(rsa.flag & R_PUBOUT || rsa.flag & R_PUBIN) ? buf[16] = 0x00 : 0;
	(rsa.flag & R_PUBOUT || rsa.flag & R_PUBIN) ? buf[19] = 0x00 : 0;
	i = -1;
	while (++i < len)
		if (buf[i] == 0x02 && buf[i + 2] == 0xFF)
			buf[i + 2] = 0x00;
	ft_putstr_fd((rsa.flag & R_PUBOUT || rsa.flag & R_PUBIN) ?\
	PUB_BEG : PRIV_BEG, rsa.fd_out);
	base64_nstr_fd(buf, len, rsa.fd_out);
	ft_putstr_fd((rsa.flag & R_PUBOUT || rsa.flag & R_PUBIN) ?\
	PUB_END : PRIV_END, rsa.fd_out);
	rsa.fd_out > 1 ? close(rsa.fd_out) : 0;
}

void			rsa_out_options(t_rsa_out rsa, t_rsa gg, char option)
{
	if (option == 'o')
	{
		ft_putstr_fd("writing RSA key\n", 2);
		rsa_encode_out(rsa, gg);
	}
	else if (option == 'c' && !(option = 0))
	{
		if ((gg.p * gg.q != gg.n) && (option |= 0x1))
			ft_putstr_fd(N_NOT_PQ, rsa.fd_out);
		if (!(ft_is_primary(gg.p, 9.0F)) && (option |= 0x1))
			ft_putstr_fd(P_NOT_PRIME, rsa.fd_out);
		if (!(ft_is_primary(gg.q, 9.0F)) && (option |= 0x1))
			ft_putstr_fd(Q_NOT_PRIME, rsa.fd_out);
		if (mulmod(gg.q, gg.iqmp, gg.p) != 1 && (option |= 0x1))
			ft_putstr_fd(NOT_INV_Q, rsa.fd_out);
		if ((mulmod(gg.dmp1, gg.e, gg.p - 1) != 1 ||\
			mulmod(gg.dmq1, gg.e, gg.q - 1) != 1) && (option |= 0x1))
			ft_putstr_fd(DE_NOT_CONG, rsa.fd_out);
	}
	if (!option)
		ft_putstr_fd("RSA key ok\n", rsa.fd_out);
}
