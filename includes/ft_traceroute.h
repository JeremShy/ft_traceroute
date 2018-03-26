#ifndef TRACEROUTE_H
# define TRACEROUTE_H

# include <libft.h>
# include <stdio.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
# include <arpa/inet.h>

typedef struct	s_data
{
	pid_t			pid;
	int				sock;
	char			*rhost;
	struct addrinfo	*res;
	uint32_t		ttl;
	char			rp[20];
	char			**av;
}				t_data;

int		init_socket(t_data *data);


#endif
