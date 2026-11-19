// libFuzzer harness for nfqws's packet path: dpi_desync_packet(), the function the NFQUEUE
// callback (nfq_cb -> processPacketData) hands every queued packet to.
//
// nfqws.c is compiled into this TU so the REAL option parser (main) configures the desync
// profiles, loads lists, initializes conntrack, exactly as the daemon does. Only two things are
// redirected, both environment and not packet-processing code:
//   * the call `nfq_main()` (open NFQUEUE netlink socket, drop privileges, seccomp, recv loop)
//     becomes fuzz_nfq_loop(), which returns at once — the fuzzer is the packet source instead;
//   * cleanup_params(), which main runs on return, is skipped so the configured params survive.
// libc socket() is wrapped (-Wl,--wrap=socket) to refuse SOCK_RAW, so rawsend() never transmits
// the crafted fakes/segments on a real network (as an unprivileged nfqws would see it).
//
// Modes (FUZZ_MODE): 1 = raw L3 packets, 2 = TCP payload in a synthesized flow, 3 = UDP datagrams.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#ifndef FUZZ_MODE
#define FUZZ_MODE 1
#endif

static int fuzz_nfq_loop(void);
#define main nfqws_main
// `static int nfq_main(void)` -> nfq_main_orig(void) (kept, unused); the call `nfq_main()` -> loop
#define NFQSEL_void nfq_main_orig(void)
#define NFQSEL_ fuzz_nfq_loop()
#define nfq_main(x) NFQSEL_##x
#define cleanup_params(p) fuzz_keep_params(p)
#include "../../nfq/nfqws.c"
#undef main
#undef cleanup_params

void fuzz_keep_params(struct params_s *p) { (void)p; }
static int fuzz_nfq_loop(void) { return 0; }

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol)
{
	if ((type & 0xF) == SOCK_RAW) { errno = EPERM; return -1; }
	return __real_socket(domain, type, protocol);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	char *args[] = {
		"nfqws", "--qnum=200",
		// profile 1: TCP (http/tls) with the stream modifications and every split marker
		"--filter-tcp=80,443",
		"--dpi-desync=fake,multisplit",
		"--dpi-desync-split-pos=1,midsld,host+1,sniext+1,method+2",
		"--dpi-desync-fooling=md5sig,badseq,badsum",
		"--dpi-desync-fake-tls-mod=rnd,rndsni,dupsid,padencap",
		"--hostcase", "--domcase", "--hostnospace",
		"--dpi-desync-cutoff=n8",
		"--new",
		// profile 2: TCP other ports, fakedsplit + seqovl
		"--filter-tcp=1-65535",
		"--dpi-desync=fakedsplit",
		"--dpi-desync-split-pos=2,host",
		"--dpi-desync-split-seqovl=1",
		"--dpi-desync-any-protocol",
		"--new",
		// profile 3: UDP (QUIC/wireguard/dht/stun/discord detection + fake)
		"--filter-udp=1-65535",
		"--dpi-desync=fake,udplen",
		"--dpi-desync-any-protocol",
		"--dpi-desync-repeats=2",
		NULL
	};
	int n = (int)(sizeof(args) / sizeof(args[0])) - 1;
	// the option parser edits its arguments in place, like a real argv
	for (int i = 0; i < n; i++) args[i] = strdup(args[i]);
	optind = 0;
	nfqws_main(n, args);
	return 0;
}

// Reset the per-flow state (conntrack, ip cache) so each input's result depends only on it.
static void reset_state(void)
{
	ConntrackPoolDestroy(&params.conntrack);
	ConntrackPoolInit(&params.conntrack, 10, params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);
	ipcacheDestroy(&params.ipcache);
	srandom(1);
}

// One packet: an exactly-sized heap copy, like the bytes nfq_get_payload() hands nfq_cb.
static void feed(const uint8_t *pkt, size_t len)
{
	uint8_t *buf = malloc(len ? len : 1);
	if (!buf) return;
	memcpy(buf, pkt, len);
	size_t l = len;
	dpi_desync_packet(0, "", "", buf, &l);
	free(buf);
}

#if FUZZ_MODE != 1
static uint16_t csum16(const uint8_t *p, size_t n, uint32_t s)
{
	for (; n > 1; n -= 2, p += 2) s += (p[0] << 8) | p[1];
	if (n) s += p[0] << 8;
	while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
	return (uint16_t)~s;
}

// IPv4 + L4 header around a payload. proto 6 (flags/seq/ack used) or 17.
static void feed_l4(uint8_t proto, uint16_t sport, uint16_t dport, int out, uint8_t flags,
		    uint32_t seq, uint32_t ack, const uint8_t *pl, size_t plen)
{
	size_t l4h = proto == 6 ? 20 : 8, len = 20 + l4h + plen;
	if (len > 0xFFFF) return;
	uint8_t *p = calloc(1, len);
	if (!p) return;
	static const uint8_t cli[4] = {192, 168, 1, 2}, srv[4] = {93, 184, 216, 34};
	p[0] = 0x45; p[2] = len >> 8; p[3] = len; p[6] = 0x40; p[8] = 64; p[9] = proto;
	memcpy(p + 12, out ? cli : srv, 4); memcpy(p + 16, out ? srv : cli, 4);
	uint16_t c = csum16(p, 20, 0); p[10] = c >> 8; p[11] = c;
	uint8_t *t = p + 20;
	uint16_t sp = out ? sport : dport, dp = out ? dport : sport;
	t[0] = sp >> 8; t[1] = sp; t[2] = dp >> 8; t[3] = dp;
	if (proto == 6)
	{
		t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq;
		t[8] = ack >> 24; t[9] = ack >> 16; t[10] = ack >> 8; t[11] = ack;
		t[12] = 5 << 4; t[13] = flags; t[14] = 0xFF; t[15] = 0xFF;
	}
	else { t[4] = (8 + plen) >> 8; t[5] = 8 + plen; }
	if (plen) memcpy(t + l4h, pl, plen);
	uint32_t ps = (p[12] << 8 | p[13]) + (p[14] << 8 | p[15]) + (p[16] << 8 | p[17]) + (p[18] << 8 | p[19]) + proto + l4h + plen;
	c = csum16(t, l4h + plen, ps);
	if (proto == 6) { t[16] = c >> 8; t[17] = c; } else { t[6] = c >> 8; t[7] = c; }
	feed(p, len);
	free(p);
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	reset_state();
#if FUZZ_MODE == 1
	// Raw L3 packets (IPv4/IPv6 with any L4), each as [u16 big-endian length][bytes].
	while (size >= 2)
	{
		size_t l = (size_t)data[0] << 8 | data[1];
		data += 2; size -= 2;
		if (l > size) l = size;
		feed(data, l);
		data += l; size -= l;
	}
#elif FUZZ_MODE == 2
	// byte0: bit0 selects port 443/80, bits1-2 number of client segments (1..3);
	// the rest is the client's stream payload (e.g. a TLS ClientHello or HTTP request),
	// sent after a SYN / SYN-ACK so conntrack tracks a real flow.
	if (size < 1) return -1;
	uint16_t dport = (data[0] & 1) ? 80 : 443;
	unsigned nseg = 1 + ((data[0] >> 1) % 3);
	data++; size--;
	uint32_t cseq = 1000, sseq = 50000;
	feed_l4(6, 40000, dport, 1, 0x02, cseq, 0, NULL, 0);
	feed_l4(6, 40000, dport, 0, 0x12, sseq, cseq + 1, NULL, 0);
	cseq++;
	feed_l4(6, 40000, dport, 1, 0x10, cseq, sseq + 1, NULL, 0);
	size_t chunk = nseg > 1 ? (size + nseg - 1) / nseg : size;
	for (unsigned i = 0; i < nseg && (size || i == 0); i++)
	{
		size_t l = chunk < size ? chunk : size;
		feed_l4(6, 40000, dport, 1, 0x18, cseq, sseq + 1, data, l);
		cseq += l; data += l; size -= l;
	}
#else
	// byte0 selects the destination port; then datagrams as [u16 big-endian length][bytes]
	// (a short/oversized length takes the rest), sent client -> server in one UDP flow.
	static const uint16_t ports[8] = {443, 51820, 3478, 6881, 50000, 500, 53, 4433};
	if (size < 1) return -1;
	uint16_t dport = ports[data[0] & 7];
	data++; size--;
	do
	{
		size_t l = size;
		if (size >= 2)
		{
			size_t w = (size_t)data[0] << 8 | data[1];
			data += 2; size -= 2;
			l = w <= size ? w : size;
		}
		feed_l4(17, 40000, dport, 1, 0, 0, 0, data, l);
		data += l; size -= l;
	} while (size);
#endif
	return 0;
}
