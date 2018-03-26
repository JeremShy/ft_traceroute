#include <ft_traceroute.h>

int	analyse_received_packet(t_data *data, char *buffer, size_t size)
{
	struct icmphdr	*icmp_header;
	struct iphdr	*ip_header;
	uint32_t		source;
	char			dst[20];

	ip_header = (void*)buffer;
	icmp_header = (void*)buffer + ip_header->ihl * 4;


	source = ip_header->saddr;
	inet_ntop(AF_INET, &source, dst, 20);
	printf("dst : %s\n", dst);
	if (icmp_header->type == 0 && ft_strcmp(dst, data->rp) == 0)
		return (0);
	else
		return (1);
}
