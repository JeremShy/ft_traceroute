=#include <ft_traceroute.h>

void	send_icmp_packet(t_data *data, uint8_t ttl)
{
	char			dgram[100];
	struct icmphdr	*icmp_header;
	uint16_t		*seq;

	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	ft_bzero(dgram, sizeof(dgram));
	icmp_header = (void*)dgram;
	seq = (void*)dgram + sizeof(struct icmphdr);

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;
	icmp_header->un.echo.id = htons(data->pid);
	icmp_header->un.echo.sequence = htons(data->seq);
	*seq = (uint16_t)data->seq;
	*seq = 0xDEAD;
	gettimeofday(&data->array[data->seq], NULL);
	data->seq++;
	icmp_header->checksum = checksum(dgram, sizeof(dgram));
	sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen);
}

int	analyse_icmp_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime)
{
	struct icmphdr	*icmp_header;
	struct iphdr	*ip_header;
	uint32_t		source;
	char			dst[20];
	struct icmphdr	*other_icmp_hdr;
	struct iphdr	*other_iphdr;

	ip_header = (void*)buffer;
	icmp_header = (void*)buffer + ip_header->ihl * 4;

	source = ip_header->saddr;
	inet_ntop(AF_INET, &source, dst, 20);
	printf("dst : %s\n", dst);
	if (icmp_header->type == 0 || (icmp_header->type == 3 && icmp_header->type == 3) )
		return (0);

	other_iphdr = (void*)buffer + ip_header->ihl + 8;
	other_icmp_hdr = (void*)buffer +  ip_header->ihl * 4 + 8 + 5 * 4;
	printf("first ihl * 4: %d\n", ip_header->ihl * 4);
	printf("written seq : %d\n",  ntohs(other_icmp_hdr->un.echo.sequence));
	return (1);
}
