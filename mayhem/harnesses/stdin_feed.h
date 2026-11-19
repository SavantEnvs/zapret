// Shared by the stdin-tool harnesses: put the fuzz input on stdin, as the CLI reads it.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static int stdin_from(const uint8_t *data, size_t size)
{
	static char path[256];
	if (!*path)
	{
		const char *t = getenv("TMPDIR");
		snprintf(path, sizeof(path), "%s/zapret-fuzz-XXXXXX", (t && *t) ? t : "/tmp");
		int fd = mkstemp(path);
		if (fd < 0) return -1;
		close(fd);
	}
	FILE *f = fopen(path, "wb");
	if (!f) return -1;
	if (size && fwrite(data, 1, size, f) != size) { fclose(f); return -1; }
	fclose(f);
	if (!freopen(path, "rb", stdin)) return -1;
	return 0;
}
