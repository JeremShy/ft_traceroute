#include <ft_traceroute.h>

void	print_usage(char *av)
{
		dprintf(2, "Usage :\n\t%s [-h]\n\t%s destination\n", av, av);	
}

int main(int ac, char **av)
{
	t_data	data;

	if (ac == 1 || ft_strcmp(av[1], "-h") == 0)
	{
		print_usage(av[0]);
		return (0);
	}
	if (getuid() != 0)
	{
		dprintf(2, "%s: You need to be root in order to use this program.\n", av[0]);
		return (1);
	}
	data.pid = getpid();
	data.av = av;
	data.rhost = av[1];
	data.ttl = 1;
	if (!init_socket(&data))
		return (2);
	
	return (0);
}
