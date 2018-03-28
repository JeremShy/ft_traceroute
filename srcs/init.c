#include <ft_traceroute.h>

int	init_icmp_socket(t_data *data)
{
	struct addrinfo hints;
	struct	in_addr source;

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
		source = ((struct sockaddr_in*)(data->res->ai_addr))->sin_addr;
		char *res = inet_ntoa(source);
		ft_strncpy(data->rp, res, 19);
	}
	else if (data->res->ai_family == AF_INET6)
	{
		dprintf(2, "IPV6 not supported.\n");
		exit(-1);
	}
	setsockopt(data->sock, IPPROTO_IP, IP_TTL, &data->ttl, sizeof(data->ttl));
	return (1);
	
}

int	init_udp_socket(t_data *data)
{
	struct addrinfo hints;
	struct	in_addr source;

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
		source = ((struct sockaddr_in*)(data->res->ai_addr))->sin_addr;
		char *res = inet_ntoa(source);
		ft_strncpy(data->rp, res, 19);

	}
	else if (data->res->ai_family == AF_INET6)
	{
		dprintf(2, "IPV6 not supported.\n");
		exit(-1);
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
