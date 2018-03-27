#include <ft_traceroute.h>

void	print_usage(char *av)
{
		dprintf(2, "Usage :\n\t%s [-h]\n\t%s destination\n", av, av);	
}

int8_t	analyse_specific_av(t_data *data, int i, int ac, char **av)
{
	(void)ac; //Left for possible later use.
	int	j;

	j = 1;
	while (av[i][j])
	{
		if (av[i][j] == 'I')
		{
			printf("The scan wille be in icmp.\n");
			data->probe_type = PROBE_TYPE_ICMP;
		}
		else if (av[i][j] == 'h')
			return (-1);
		else
		{
			dprintf(2, "%s: Unknown option `%c'\n", av[0], av[i][j]);
			return (0);
		}
		j++;
	}
	return (1);
}

int8_t	parse_av(t_data *data, int ac, char **av)
{
	int	i;
	int	ret;

	i = 1;
	while (i < ac && av[i][0] == '-' && ft_strcmp(av[i], "--") != 0)
	{
		ret = analyse_specific_av(data, i, ac, av);
		if (ret == 0 || ret == -1)
			return (ret);
		i++;
	}
	if (i < ac && ft_strcmp(av[i], "--") == 0)
		i++;
	if (i >= ac)
	{
		dprintf(2, "Error: %s: Please enter a host.\n", av[0]);
		return (0);
	}
	data->rhost = av[i];
	return (1);
}

int main(int ac, char **av)
{
	t_data	data;
	int		ret;

	data.probe_type = PROBE_TYPE_DEFAULT;
	ret = parse_av(&data, ac, av);
	if (ret == -1)
	{
		print_usage(av[0]);
		return (0);
	}
	else if (ret == 0)
		return (1);
	if (getuid() != 0)
	{
		dprintf(2, "%s: You need to be root in order to use this program.\n", av[0]);
		return (2);
	}
	printf("Protocol : %d\n", data.probe_type);
	data.pid = getpid();
	data.av = av;
	data.ttl = 1;
	data.seq = 0;
	data.probes_per_hops = 3;
	data.max_hops = 30;
	if ((data.array = malloc(sizeof(struct timeval) * data.probes_per_hops * data.max_hops)) == 0)
	{
		printf("Error while trying to allocate room for an array.\n");
		return (3);
	}
	ft_bzero(data.array, sizeof(struct timeval) * data.probes_per_hops * data.max_hops);
	if (!init_socket(&data))
		return (4);
	printf("traceroute to %s (%s)\n", data.rhost, data.rp);
	do_traceroute(&data);
	return (0);
}

NULL
