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

# define PROBE_TYPE_ICMP	1
# define PROBE_TYPE_TCP		6
# define PROBE_TYPE_UDP		17

# define PROBE_TYPE_DEFAULT	PROBE_TYPE_UDP

typedef struct	s_data
{
	pid_t			pid;
	int				sock;
	int				recv_sock;
	char			*rhost;
	struct addrinfo	*res;
	uint8_t			ttl;
	uint16_t		seq;
	char			rp[20];
	char			**av;
	int8_t			probe_type;
	int8_t			probes_per_hops;
	int8_t			max_hops;
	int8_t			*array;
}				t_data;

int		init_socket(t_data *data);

void	do_traceroute(t_data *data);
uint16_t checksum(void *dgram, size_t size);

int		analyse_icmp_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime);
int		analyse_udp_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime);

void	print_memory(char *start, size_t size);
void	print_icmp_hdr(struct icmphdr *hdr);

void	send_icmp_packet(t_data *data, uint8_t	ttl);

void	send_udp_packet(t_data *data, uint8_t ttl);


#endif
