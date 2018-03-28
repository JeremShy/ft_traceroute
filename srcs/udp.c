#include <ft_traceroute.h>

void	send_udp_packet(t_data *data, uint8_t ttl)
{
	char			dgram[60];
	uint16_t		*seq;

	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	ft_bzero(dgram, sizeof(dgram));
	seq = (void*)dgram;

	*seq = (uint16_t)data->seq;
	((struct sockaddr_in*)data->res->ai_addr)->sin_port = htons(33434 + data->seq);
	data->seq++;
	if (sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen) != sizeof(dgram))
		dprintf(2, "Write error.\n");
	gettimeofday(&(data->array[data->seq - 1]), NULL);
}

int	analyse_udp_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime)
{
	struct icmphdr	*icmp_header;
	struct iphdr	*ip_header;
	struct in_addr		source;
	uint16_t		*seq_ptr;
	uint16_t		seq;
	float	rtt;

	ip_header = (void*)buffer;
	icmp_header = (void*)buffer + ip_header->ihl * 4;
	if ((void*)icmp_header > (void*)buffer + size)
		return (0);
	source.s_addr = ip_header->saddr;
	char *ptr = inet_ntoa(source);
	ft_strncpy(data->actual_dst, ptr, 20);
	if (icmp_header->type == 0 || (icmp_header->type == 3 && icmp_header->type == 3) )
		data->must_stop = 1;
	seq_ptr = (void*)buffer +  ip_header->ihl * 4 + 8 + 20 + 2;
	if ((void*)seq_ptr > (void*)buffer + size)
		return (0);
	seq = ntohs(*seq_ptr) - 33434;
	if (seq >= data->max_hops * data->probes_per_hops)
		return (0);
	rtt = (recvtime.tv_sec - data->array[seq].tv_sec) * 1000 + ((recvtime.tv_usec / 1000.0f) - (data->array[seq].tv_usec / 1000.0f));
	
	if (rtt < 0)
		exit(0);
	add_tl(&(data->list), create_tl(rtt, 0));
	return (1);
}
