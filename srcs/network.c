#include <ft_traceroute.h>

static uint16_t checksum(void *dgram, size_t size)
{
	uint16_t *tmp;
	size_t sum;

	tmp = dgram;
	sum = 0;
	while (size > 1)
	{
		sum += *tmp;
		tmp++;
		size -= 2;
	}
	if (size == 1)
		sum += *(unsigned char*)tmp;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (~sum);
}

void	receive_icmp_packet(t_data *data)
{
	struct msghdr msghdr;
	char buffer[200];
	struct timeval recvtime;
	struct iovec iov;
	int		analysis;

	ft_bzero(buffer, sizeof(buffer));
	ft_bzero(&msghdr, sizeof(msghdr));

	msghdr.msg_namelen = data->res->ai_addrlen;

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;

	// printf("Waiting for a message...\n");
	int r = recvmsg(data->sock, &msghdr, 0);
	if (r == -1)
	{
		printf("*\n");
		return ;
	}
	gettimeofday(&recvtime, NULL);
	// printf("Message received !\n");
	buffer[r] = 0;
	if (!analyse_received_packet(data, buffer, r))
	{
		exit(0);
	}
}

void	send_icmp_packet(t_data *data, uint8_t	ttl)
{
	char			dgram[32];
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
	gettimeofday(tv, NULL);
	data->seq++;
	icmp_header->checksum = checksum(dgram, sizeof(dgram));
	sendto(data->sock, dgram, sizeof(dgram), 0, data->res->ai_addr, data->res->ai_addrlen);
}

void	do_traceroute(t_data *data)
{
	int	ttl;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 50000;
	setsockopt(data->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	ttl = 1;
	while (ttl <= 30)
	{
		send_icmp_packet(data, ttl);
		// send_icmp_packet(data, ttl);
		// send_icmp_packet(data, ttl);
		receive_icmp_packet(data);
		// receive_icmp_packet(data);
		// receive_icmp_packet(data);
		ttl++;
	}
}
