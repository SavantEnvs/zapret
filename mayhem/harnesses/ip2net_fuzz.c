// libFuzzer harness for ip2net: an IP / CIDR / range list on stdin, aggregated into subnets.
// byte0 picks the mode the CLI is run in (bit0: -6 vs -4, bits1-2: one of a few fixed option
// sets); the rest is the stdin list. ip2net's main parses argv afresh every call.
#include <stdint.h>
#include <stddef.h>
#define main ip2net_main
#include "../../ip2net/ip2net.c"
#undef main
#include "stdin_feed.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1) return -1;
	int v6 = data[0] & 1, opt = (data[0] >> 1) & 3;
	char *a4[][4] = { {"ip2net", "-4", NULL}, {"ip2net", "-4", "--prefix-length=22-30", NULL},
		{"ip2net", "-4", "--v4-threshold=1/2", NULL}, {"ip2net", "-4", "--prefix-length=8-31", NULL} };
	char *a6[][4] = { {"ip2net", "-6", NULL}, {"ip2net", "-6", "--prefix-length=56-64", NULL},
		{"ip2net", "-6", "--v6-threshold=2", NULL}, {"ip2net", "-6", "--prefix-length=32-127", NULL} };
	char **argv = v6 ? a6[opt] : a4[opt];
	int argc = 0;
	while (argv[argc]) argc++;
	if (stdin_from(data + 1, size - 1)) return 0;
	optind = 0;
	ip2net_main(argc, argv);
	fflush(stdout);
	return 0;
}
