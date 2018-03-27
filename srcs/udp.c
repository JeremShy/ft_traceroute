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
	gettimeofday(&data->array[data->seq], NULL);
	data->seq++;
	if (sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen) != sizeof(dgram))
	{
		dprintf(2, "Write error.\n");
	}
}

int	analyse_udp_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime)
{
	struct icmphdr	*icmp_header;
	struct iphdr	*ip_header;
	uint32_t		source;
	char			dst[20];
	struct iphdr	*other_iphdr;
	uint16_t		*seq;

	ip_header = (void*)buffer;
	icmp_header = (void*)buffer + ip_header->ihl * 4;

	source = ip_header->saddr;
	inet_ntop(AF_INET, &source, dst, 20);
	printf("dst : %s\n", dst);
	if (icmp_header->type == 0 || (icmp_header->type == 3 && icmp_header->type == 3) )
		return (0);

	other_iphdr = (void*)buffer + ip_header->ihl + 8;
	seq = (void*)buffer +  ip_header->ihl * 4 + 8 + 5 * 4 + 2;
	printf("first ihl * 4: %d\n", ip_header->ihl * 4);
	printf("written seq : %d\n",  ntohs(*seq) - 33434);
	return (1);
}
