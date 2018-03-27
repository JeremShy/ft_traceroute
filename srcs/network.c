#include <ft_traceroute.h>

uint16_t checksum(void *dgram, size_t size)
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

	ft_bzero(buffer, sizeof(buffer));
	ft_bzero(&msghdr, sizeof(msghdr));

	msghdr.msg_namelen = data->res->ai_addrlen;

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;

	int r = recvmsg(data->recv_sock, &msghdr, 0);
	if (r == -1)
	{
		printf("*\n");
		return ;
	}
	gettimeofday(&recvtime, NULL);
	buffer[r] = 0;
	if (!analyse_received_packet(data, buffer, r))
	{
		exit(0);
	}
}

static void	probe(t_data *data, int ttl)
{
	if (data->probe_type == PROBE_TYPE_ICMP)
		send_icmp_packet(data, ttl);
	else if (data->probe_type == PROBE_TYPE_UDP)
		send_udp_packet(data, ttl);
}

void	do_traceroute(t_data *data)
{
	int	ttl;
	int	i;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 50000;
	setsockopt(data->recv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	ttl = 30;
	while (ttl <= 30)
	{
		i = 0;
		while (i < 3)
		{
			probe(data, ttl);
			receive_icmp_packet(data);
			i++;
		}
		ttl++;
	}
}
