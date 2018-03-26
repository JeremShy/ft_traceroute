#ifndef TRACEROUTE_H
# define TRACEROUTE_H

# include <libft.h>
# include <stdio.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <netinet/ip_icmp.h>
# include <sys/time.h>
# include <errno.h>

typedef struct	s_data
{
	pid_t			pid;
	int				sock;
	char			*rhost;
	struct addrinfo	*res;
	uint8_t			ttl;
	uint16_t		seq;
	char			rp[20];
	char			**av;
}				t_data;

int		init_socket(t_data *data);

void	do_traceroute(t_data *data);

int		analyse_received_packet(t_data *data, char *buffer, size_t size);

void	print_memory(char *start, size_t size);
void	print_icmp_hdr(struct icmphdr *hdr);
#endif
