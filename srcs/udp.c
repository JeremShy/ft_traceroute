#include <ft_traceroute.h>

void	send_udp_packet(t_data *data, uint8_t ttl)
{
	char			dgram[60];
	struct timeval	*tv;
	uint16_t		*seq;

	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	ft_bzero(dgram, sizeof(dgram));
	seq = (void*)dgram;
	tv = (void*)dgram + sizeof(uint16_t);

	*seq = (uint16_t)data->seq;
	gettimeofday(tv, NULL);
	data->seq++;
	if (sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen) != sizeof(dgram))
	{
		dprintf(2, "Write error.\n");
	}
}
