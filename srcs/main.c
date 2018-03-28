#include <ft_traceroute.h>

void	print_usage(char *av)
{
		dprintf(2, "Usage :\n\t%s [-h]\n\t%s [-m max_hops] [-q nqueries] [-f first_ttl] [-I | -Q] destination\n", av, av);	
}

int		get_nbr(int *i, int ac, char **av, int *j, int *error)
{
	int	ret;

	ret = 0;
	if (av[*i][*j + 1] != '\0')
	{
		if (ft_isdigit(av[*i][*j + 1]))
			ret = ft_atoi(&av[*i][*j + 1]);
		else
			*error = 1;
		(*i)++;
		*j = 0;
		return (ret);
	}
	if (*i == ac - 1)
	{
		*error = 1;
		return (0);
	}
	(*i)++;
	*j = 0;
	if (ft_isdigit(av[*i][*j]))
		ret = ft_atoi(&av[*i][*j]);
	else
		*error = 1;
	(*i)++;
	*j = 0;
	return (ret);
}

int8_t	analyse_specific_av(t_data *data, int *i, int ac, char **av)
{
	(void)ac; //Left for possible later use.
	int	j;
	int	error;

	j = 1;
	while (av[*i][j])
	{
		if (av[*i][j] == 'I')
			data->probe_type = PROBE_TYPE_ICMP;
		else if (av[*i][j] == 'U')
			data->probe_type = PROBE_TYPE_UDP;
		else if (av[*i][j] == 'm')
		{
			error = 0;
			data->max_hops = get_nbr(i, ac, av, &j, &error);
			if (error || data->max_hops <= 0)
				return (-1);
			(*i)--;
			return (1);
		}
		else if (av[*i][j] == 'q')
		{
			error = 0;
			data->probes_per_hops = get_nbr(i, ac, av, &j, &error);
			if (error || data->probes_per_hops <= 0)
				return (-1);
			(*i)--;
			return (1);
		}
		else if (av[*i][j] == 'f')
		{
			error = 0;
			data->ttl = get_nbr(i, ac, av, &j, &error);
			if (error || data->ttl <= 0)
				return (-1);
			(*i)--;
			return (1);
		}
		else if (av[*i][j] == 'h')
			return (-1);
		else
		{
			dprintf(2, "%s: Unknown option `%c'\n", av[0], av[*i][j]);
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
		ret = analyse_specific_av(data, &i, ac, av);
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
	data.probes_per_hops = 3;
	data.max_hops = 30;
	data.ttl = 1;
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
	data.pid = getpid();
	data.av = av;
	data.seq = 0;
	data.list = NULL;
	data.must_stop = 0;
	ft_bzero(data.actual_dst, sizeof(data.actual_dst));
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
