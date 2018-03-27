#include <ft_traceroute.h>

int	init_icmp_socket(t_data *data)
{
	struct addrinfo hints;

	ft_bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	data->recv_sock = socket(AF_INET, SOCK_RAW, 1); // proto ICMP : 1
	if (data->probe_type == PROBE_TYPE_ICMP)
		data->sock = data->recv_sock;

	if ((getaddrinfo(data->rhost, NULL, &hints, &(data->res)) != 0) || !(data->res))
	{
		dprintf(2, "%s: %s: Name not known\n", data->av[0], data->rhost);
		return (0);
	}

	if (data->res->ai_family == AF_INET)
	{
		if (inet_ntop(data->res->ai_family, &((struct sockaddr_in*)(data->res->ai_addr))->sin_addr, data->rp, sizeof(data->rp)) == 0)
		{
			dprintf(2, "inet_ntop failed.\n");
			return (0);
		}
	}
	else if (data->res->ai_family == AF_INET6)
	{
		if (inet_ntop(data->res->ai_family, &((struct sockaddr_in6*)(data->res->ai_addr))->sin6_addr, data->rp, sizeof(data->rp)) == 0)
		{
			dprintf(2, "inet_ntop failed.\n");
			return (0);
		}
	}
	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &data->ttl, sizeof(data->ttl));
	return (1);
	
}

int	init_udp_socket(t_data *data)
{
	struct addrinfo hints;

	ft_bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 17;
	data->sock = socket(AF_INET, SOCK_DGRAM, 17);

	if ((getaddrinfo(data->rhost, "33434", &hints, &(data->res)) != 0) || !(data->res))
	{
		dprintf(2, "%s: %s: Name not known\n", data->av[0], data->rhost);
		return (0);
	}

	if (data->res->ai_family == AF_INET)
	{
		if (inet_ntop(data->res->ai_family, &((struct sockaddr_in*)(data->res->ai_addr))->sin_addr, data->rp, sizeof(data->rp)) == 0)
		{
			dprintf(2, "inet_ntop failed.\n");
			return (0);
		}
	}
	else if (data->res->ai_family == AF_INET6)
	{
		if (inet_ntop(data->res->ai_family, &((struct sockaddr_in6*)(data->res->ai_addr))->sin6_addr, data->rp, sizeof(data->rp)) == 0)
		{
			dprintf(2, "inet_ntop failed.\n");
			return (0);
		}
	}
	return (1);
}

int init_socket(t_data *data)
{
	if (init_icmp_socket(data) == 0)
		return (0);
	if (data->probe_type == PROBE_TYPE_UDP)
		return (init_udp_socket(data));
	return (1);
}
