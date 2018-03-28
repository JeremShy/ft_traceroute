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
	char buffer[1024];
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
		add_tl(&(data->list), create_tl(0.0f, 1));
		return ;
	}
	gettimeofday(&recvtime, NULL);
	buffer[r] = 0;
	if (data->probe_type == PROBE_TYPE_UDP)
	{
		if (!analyse_udp_received_packet(data, buffer, r, recvtime))
			exit(0);
	}
	else if (data->probe_type == PROBE_TYPE_ICMP)
	{
		if (!analyse_icmp_received_packet(data, buffer, r, recvtime))
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
	int	i;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	if (setsockopt(data->recv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval)) == -1)
	{
		perror("");
	}
	if (setsockopt(data->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval)) == -1)
	{
		perror("");
	}

	while (data->ttl <= data->max_hops)
	{
		i = 0;
		while (i < data->probes_per_hops)
		{
			probe(data, data->ttl);
			receive_icmp_packet(data);
			i++;
		}
		print_time_list(data, data->list, data->ttl);
		free_tl(data->list);
		if (data->must_stop)
			return ;
		data->list = NULL;
		ft_bzero(data->actual_dst, sizeof(data->actual_dst));
		(data->ttl)++;
	}
}
