#include <ft_traceroute.h>

void	send_icmp_packet(t_data *data, uint8_t ttl)
{
	char			dgram[100];
	struct icmphdr	*icmp_header;

	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	ft_bzero(dgram, sizeof(dgram));
	icmp_header = (void*)dgram;

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;
	icmp_header->un.echo.id = htons(data->pid);
	icmp_header->un.echo.sequence = htons(data->seq);
	data->seq++;
	icmp_header->checksum = checksum(dgram, sizeof(dgram));
	sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen);
	gettimeofday(&data->array[data->seq - 1], NULL);
}

int	analyse_icmp_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime)
{
	struct icmphdr	*icmp_header;
	struct iphdr	*ip_header;
	uint32_t		source;
	struct icmphdr	*other_icmp_hdr;
	int				seq;
	float			rtt;

	ip_header = (void*)buffer;
	icmp_header = (void*)buffer + ip_header->ihl * 4;
	if ((void*)icmp_header > (void*)buffer + size)
		return (0);

	source = ip_header->saddr;
	inet_ntop(AF_INET, &source, data->actual_dst, 20);
	if (icmp_header->type == 0 || (icmp_header->type == 3 && icmp_header->type == 3) )
		return (0);
	other_icmp_hdr = (void*)buffer +  ip_header->ihl * 4 + 8 + 20;
	if ((void*)other_icmp_hdr > (void*)buffer + size)
		return (0);
	seq = ntohs(other_icmp_hdr->un.echo.sequence);
	if (seq >= data->max_hops * data->probes_per_hops)
		return (0);
	// printf("first ihl * 4: %d\n", ip_header->ihl * 4);
	// printf("written seq : %d\n",  seq);
	rtt = (recvtime.tv_sec - data->array[seq].tv_sec) + recvtime.tv_usec / 1000.0 - data->array[seq].tv_usec / 1000.0;
	add_tl(&(data->list), create_tl(rtt, 0));
	return (1);
}
