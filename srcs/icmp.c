#include <ft_traceroute.h>

void	send_icmp_packet(t_data *data, uint8_t ttl)
{
	char			dgram[100];
	struct icmphdr	*icmp_header;
	struct timeval	*tv;
	uint16_t		*seq;

	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	ft_bzero(dgram, sizeof(dgram));
	icmp_header = (void*)dgram;
	seq = (void*)dgram + sizeof(struct icmphdr);
	tv = (void*)dgram + sizeof(struct icmphdr) + sizeof(uint16_t);

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;
	icmp_header->un.echo.id = htons(data->pid);
	icmp_header->un.echo.sequence = htons(data->seq);
	*seq = (uint16_t)data->seq;
	*seq = 0xDEAD;
	gettimeofday(tv, NULL);
	data->seq++;
	icmp_header->checksum = checksum(dgram, sizeof(dgram));
	sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen);
}
