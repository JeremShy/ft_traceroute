#include <ft_traceroute.h>

t_time_list *create_tl(float time, int8_t is_star)
{
	t_time_list	*node;

	if ((node = malloc(sizeof(t_time_list))) == NULL)
	{
		dprintf(2, "malloc error.\n");
		exit (5);
	}
	node->time = time;
	node->is_star = is_star;
	node->next = NULL;
	return (node);
}

void	add_tl(t_time_list **list, t_time_list *node)
{
	t_time_list	*tmp;

	if (!(*list))
		*list = node;
	else
	{
		tmp = *list;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = node;
	}
}

void	free_tl(t_time_list *list)
{
	t_time_list	*tmp;

	while (list)
	{
		tmp = list->next;
		free(list);
		list = tmp;
	}
}

void	print_time_list(t_data *data, t_time_list *list, int ttl)
{
	int	tmp;

	if (data->actual_dst[0] != '\0')
		printf("%2d  %s", ttl, data->actual_dst);
	else
		printf("%2d", ttl);
	tmp = 0;
	while (list)
	{
		if (list->is_star)
		{
			if (tmp == 0)
			{
				printf("  *");
				tmp = 1;
			}
			else
				printf(" *");
		}
		else
			printf("  %.3f ms", list->time);
		list = list->next;
	}
	printf("\n");
}
