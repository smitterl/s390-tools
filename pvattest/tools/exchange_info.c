#include <stdio.h>
#include "config.h"

#include "exchange_format.h"

int main(int argc, char *argv[])
{
	g_autoptr(GError) error = NULL;
	g_autoptr(exchange_format_ctx_t) ctx = NULL;
	gboolean print_data = FALSE;

	if (argc < 2)
		return 2;

	ctx = exchange_ctx_from_file(argv[1], &error);
	if (!ctx) {
		printf("Error: %s\n", error->message);
		return 1;
	}

	print_data = (argc >= 3 && g_strcmp0(argv[2], "true") == 0);
	exchange_info_print(ctx, print_data, stdout);

	return 0;
}
