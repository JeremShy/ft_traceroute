#include <ft_traceroute.h>

int	analyse_received_packet(t_data *data, char *buffer, size_t size, struct timeval recvtime)
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
	printf("RECEIVED : \n");
	print_memory(buffer, size);
	printf("----------------\n");
	return (1);
}
