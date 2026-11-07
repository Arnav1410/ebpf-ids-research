#include <inttypes.h>
#include <stdio.h>
#include "nn_json.h"
#define U64(x) ((uint64_t)(x))
void nn_json_result(const struct nn_result *r)
{
	printf("\"flow_id\":%" PRIu64 ",\"trigger_ordinal\":%" PRIu64 ",\"timestamp_ns\":%" PRIu64 ",\"features\":[",
	       U64(r->key.flow_id), U64(r->key.trigger_ordinal), U64(r->timestamp_ns));
	for (int i = 0; i < 6; i++) printf("%s%" PRId64, i ? "," : "", (int64_t)r->features[i]);
	printf("],\"model_id\":\"");
	for (int i = 0; i < 32; i++) printf("%02x", r->identity[i]);
	printf("\",\"stage_bitmap\":%u,\"status\":%u,\"slot\":%u,\"label\":", r->stage_bitmap, r->status, r->slot);
	if (r->status || r->stage_bitmap != 63) printf("null"); else printf("%u", r->label);
	printf(",\"output\":[%d,%d],\"trigger_flags\":%u", r->logits[0], r->logits[1], r->trigger_flags);
	printf(",\"key\":{\"a_addr\":\"%u.%u.%u.%u\",\"b_addr\":\"%u.%u.%u.%u\","
	       "\"ifindex\":%u,\"a_port\":%u,\"b_port\":%u,\"protocol\":%u}",
	       r->tuple.a_addr >> 24, (r->tuple.a_addr >> 16) & 255,
	       (r->tuple.a_addr >> 8) & 255, r->tuple.a_addr & 255,
	       r->tuple.b_addr >> 24, (r->tuple.b_addr >> 16) & 255,
	       (r->tuple.b_addr >> 8) & 255, r->tuple.b_addr & 255,
	       r->tuple.ifindex, r->tuple.a_port, r->tuple.b_port, r->tuple.protocol);
}
