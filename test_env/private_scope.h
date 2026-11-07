#ifndef TEST_ENV_PRIVATE_SCOPE_H
#define TEST_ENV_PRIVATE_SCOPE_H
#include <stdbool.h>
#include <sys/stat.h>
#include <linux/types.h>
#define LAB_INTERFACE "veth-idss"
#define LAB_NAMESPACE "/run/netns/ids_server"
struct private_scope {
	int ifindex, peer_ifindex;
	unsigned char mac[6];
	struct stat namespace_identity;
};
int private_check_scope(struct private_scope *, bool capture);
int private_owned_id(const char *, const struct stat *, __u32, bool program);
#endif
