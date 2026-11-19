// libFuzzer harness for `mdig --dns-parse-query`: the DNS reply blob the CLI reads from stdin
// goes through dns_parse_query() (fread into its 8 KiB buffer, then dns_parse_print()).
#include <stdint.h>
#include <stddef.h>
#define main mdig_main
#include "../../mdig/mdig.c"
#undef main
#include "stdin_feed.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (stdin_from(data, size)) return 0;
	dns_parse_query();
	fflush(stdout);
	return 0;
}
