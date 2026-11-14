/* Scan the ID registry without opening program/map FDs. In particular, opening
 * a last-user prog-array map during teardown can schedule more deferred work.
 */
#ifndef TC_ID_SCAN_H
#define TC_ID_SCAN_H
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

static int tc_scan_ids(FILE *stream, int (*next_id)(uint32_t, uint32_t *))
{
    uint32_t previous = 0, next;
    fputc('[', stream);
    for (;;) {
        int ret = next_id(previous, &next);
        if (ret) {
            if (ret == -ENOENT) break;
            return ret;
        }
        if (next <= previous) return -EINVAL;
        fprintf(stream, "%s%u", previous ? "," : "", next);
        previous = next;
    }
    fputs("]\n", stream);
    return ferror(stream) ? -EIO : 0;
}
#endif
