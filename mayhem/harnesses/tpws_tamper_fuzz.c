// libFuzzer harness for tpws's stream tampering: tamper_out() on the client->server stream
// block (HTTP / TLS parsing, host extraction, split-pos resolution, hostcase/hostdot/hosttab/
// hostpad/methodspace/unixeol/tlsrec rewrites in the read buffer) and tamper_in() on the server
// reply, as tpws_conn.c's tamper() calls them for each recv()'d block.
// tpws.c is compiled into this TU (its main renamed) only to reuse its real option parser,
// parse_params(), which configures the desync profiles; it returns without --dry-run.
//
// Input: [u16 big-endian length of the request block][request block][reply block (rest)].
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define main tpws_main
#include "../../tpws/tpws.c"
#undef main

#define TPWS_RD_BUF (65536 + 6) // tpws_conn.c: uint8_t buf[RD_BLOCK_SIZE + 6]

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	char *args[] = {
		"tpws", "--port=988",
		// profile 1: http
		"--filter-tcp=80", "--hostcase", "--hostdot", "--hosttab", "--methodspace",
		"--unixeol", "--hostpad=256", "--domcase", "--split-pos=method+2,midsld,host+1",
		"--new",
		// profile 2: tls and anything else
		"--filter-tcp=1-65535", "--tlsrec=sniext+1", "--split-pos=1,sniext+1,midsld",
		"--disorder", "--oob", "--split-any-protocol", "--hostspell=hoSt",
		NULL
	};
	int n = (int)(sizeof(args) / sizeof(args[0])) - 1;
	for (int i = 0; i < n; i++) args[i] = strdup(args[i]); // the parser edits argv in place
	optind = 0;
	parse_params(n, args);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3) return -1;
	size_t lout = (size_t)data[0] << 8 | data[1];
	data += 2; size -= 2;
	if (lout > size) lout = size;
	if (lout > 65536) lout = 65536;
	if (size - lout > 65536) return -1; // tpws recv()s at most RD_BLOCK_SIZE per block

	ipcacheDestroy(&params.ipcache); // per-input state: ip->hostname cache

	struct sockaddr_in dest, client;
	memset(&dest, 0, sizeof(dest)); memset(&client, 0, sizeof(client));
	dest.sin_family = client.sin_family = AF_INET;
	dest.sin_port = htons((lout && data[0] == 0x16) ? 443 : 80);
	inet_pton(AF_INET, "93.184.216.34", &dest.sin_addr);
	client.sin_port = htons(40000);
	inet_pton(AF_INET, "192.168.1.2", &client.sin_addr);

	t_ctrack ct;
	memset(&ct, 0, sizeof(ct));
	apply_desync_profile(&ct, (struct sockaddr *)&dest);

	uint8_t *buf = malloc(TPWS_RD_BUF);
	if (!buf) return 0;
	size_t multisplit_pos[MAX_SPLITS];
	int multisplit_count = 0;
	uint8_t split_flags = 0;

	size_t bs = lout;
	memcpy(buf, data, lout);
	if (bs) tamper_out(&ct, (struct sockaddr *)&dest, buf, TPWS_RD_BUF, &bs, multisplit_pos, &multisplit_count, &split_flags);

	bs = size - lout;
	memcpy(buf, data + lout, bs);
	if (bs && !ct.bTamperInCutoff) tamper_in(&ct, (struct sockaddr *)&client, buf, TPWS_RD_BUF, &bs);
	rst_in(&ct, (struct sockaddr *)&client);

	free(buf);
	free(ct.hostname);
	return 0;
}
