#include <ft_traceroute.h>

static void	print_as_char(char *start, size_t size, size_t max)
{
	size_t	i;

	i = 0;
	printf("|");
	while (i < size && i < max)
	{
		if (ft_isprint(start[i]))
			printf("%c", start[i]);
		else
			printf(".");
		i++;
	}
	printf("|");
}

static void	print_as_bytes(unsigned char *start, size_t size, size_t max)
{
	size_t	i;

	i = 0;
	while (i < size && i < max)
	{
		printf("%02x ", start[i]);
		i++;
		if (i % 8 == 0)
			printf(" ");
	}
	if (max < size)
	{
		if (max < 8)
			printf("%*c", ((int)size - (int)max) * 3 + 2, ' ');
		else
			printf("%*c", ((int)size - (int)max) * 3 + 1, ' ');
	}
}

void	print_memory(char *start, size_t size)
{
	size_t	i;

	i = 0;
	while (i < size)
	{
		printf("%08lx ", (unsigned long int)(start + i));
		print_as_bytes((unsigned char*)start + i, 16, size - i);
		print_as_char(start + i, 16, size - i);
		i += 16;
		printf("\n");
	}
	printf("%08lx \n", (unsigned long int)(start + size));
}

void	print_icmp_hdr(struct icmphdr *hdr)
{
	printf("type : %d\n", hdr->type);
	printf("code : %d\n", hdr->code);
	printf("id : %d\n", ntohs(hdr->un.echo.id));
	printf("sequence : %d\n", ntohs(hdr->un.echo.sequence));
}
