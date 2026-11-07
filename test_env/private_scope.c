#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include "private_scope.h"
static bool same_namespace(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* Query the kernel directly: sysfs may still describe the original mount/netns. */
static int veth_peer(int ifindex)
{
	struct {
		struct nlmsghdr header;
		struct ifinfomsg link;
	} request = {
		.header = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
			.nlmsg_seq = 1,
		},
		.link = { .ifi_family = AF_UNSPEC, .ifi_index = ifindex },
	};
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	struct timeval timeout = { .tv_sec = 5 };
	union {
		struct nlmsghdr alignment;
		unsigned char bytes[8192];
	} buffer;
	struct nlmsghdr *header;
	int fd, remaining, result = -EPROTO;
	ssize_t size;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -errno;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		result = -errno;
		goto out;
	}
	if (sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&kernel,
		   sizeof(kernel)) != (ssize_t)sizeof(request)) {
		result = -errno;
		goto out;
	}
	size = recv(fd, buffer.bytes, sizeof(buffer.bytes), MSG_TRUNC);
	if (size < 0) {
		result = -errno;
		goto out;
	}
	if ((size_t)size > sizeof(buffer.bytes)) {
		result = -EMSGSIZE;
		goto out;
	}
	remaining = (int)size;
	for (header = (struct nlmsghdr *)buffer.bytes;
	     remaining > 0 && NLMSG_OK(header, (unsigned int)remaining);
	     header = NLMSG_NEXT(header, remaining)) {
		struct ifinfomsg *link;
		struct rtattr *attribute;
		int attributes, peer = 0;
		bool is_veth = false;

		if (header->nlmsg_seq != request.header.nlmsg_seq)
			continue;
		if (header->nlmsg_type == NLMSG_ERROR) {
			if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				result = ((struct nlmsgerr *)NLMSG_DATA(header))->error;
			if (!result)
				result = -EPROTO;
			break;
		}
		if (header->nlmsg_type != RTM_NEWLINK ||
		    header->nlmsg_len < NLMSG_LENGTH(sizeof(*link)))
			continue;
		link = NLMSG_DATA(header);
		if (link->ifi_index != ifindex)
			continue;
		attributes = IFLA_PAYLOAD(header);
		for (attribute = IFLA_RTA(link); RTA_OK(attribute, attributes);
		     attribute = RTA_NEXT(attribute, attributes)) {
			if ((attribute->rta_type & NLA_TYPE_MASK) == IFLA_LINK &&
			    RTA_PAYLOAD(attribute) == sizeof(peer))
				memcpy(&peer, RTA_DATA(attribute), sizeof(peer));
			if ((attribute->rta_type & NLA_TYPE_MASK) == IFLA_LINKINFO) {
				struct rtattr *info;
				int bytes = RTA_PAYLOAD(attribute);

				for (info = RTA_DATA(attribute); RTA_OK(info, bytes);
				     info = RTA_NEXT(info, bytes)) {
					if ((info->rta_type & NLA_TYPE_MASK) == IFLA_INFO_KIND &&
					    RTA_PAYLOAD(info) == sizeof("veth") &&
					    !memcmp(RTA_DATA(info), "veth", sizeof("veth")))
						is_veth = true;
				}
			}
		}
		result = is_veth && peer > 0 ? peer : -EPERM;
		break;
	}
out:
	close(fd);
	return result;
}

/* The only accepted scope is the existing, non-initial private server netns. */
int private_check_scope(struct private_scope *state, bool capture)
{
	struct stat current, named, initial;
	struct ifreq request = {};
	unsigned char mac[6];
	int fd, index, peer, result = 0;

	if (stat("/proc/self/ns/net", &current) || lstat(LAB_NAMESPACE, &named) ||
	    stat("/proc/1/ns/net", &initial))
		return -errno;
	if (S_ISLNK(named.st_mode) || !same_namespace(&current, &named) ||
	    !same_namespace(&current, &state->namespace_identity) ||
	    same_namespace(&current, &initial))
		return -EPERM;
	index = (int)if_nametoindex(LAB_INTERFACE);
	if (index <= 0)
		return errno ? -errno : -ENODEV;
	if (!capture && index != state->ifindex)
		return -ESTALE;
	peer = veth_peer(index);
	if (peer < 0)
		return peer;
	if (!capture && peer != state->peer_ifindex)
		return -ESTALE;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	memcpy(request.ifr_name, LAB_INTERFACE, sizeof(LAB_INTERFACE));
	if (ioctl(fd, SIOCGIFHWADDR, &request)) {
		result = -errno;
		goto out;
	}
	if (request.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		result = -EPERM;
		goto out;
	}
	memcpy(mac, request.ifr_hwaddr.sa_data, sizeof(mac));
	if (!capture && memcmp(mac, state->mac, sizeof(mac))) {
		result = -ESTALE;
		goto out;
	}
	if (ioctl(fd, SIOCGIFADDR, &request)) {
		result = -errno;
		goto out;
	}
	if (((struct sockaddr_in *)&request.ifr_addr)->sin_addr.s_addr !=
	    htonl(0x21212101)) { /* 33.33.33.1 */
		result = -EPERM;
		goto out;
	}
	if (ioctl(fd, SIOCGIFNETMASK, &request)) {
		result = -errno;
		goto out;
	}
	if (((struct sockaddr_in *)&request.ifr_netmask)->sin_addr.s_addr !=
	    htonl(0xffffff00)) {
		result = -EPERM;
		goto out;
	}
	if (capture) {
		state->ifindex = index;
		state->peer_ifindex = peer;
		memcpy(state->mac, mac, sizeof(mac));
	}
out:
	close(fd);
	return result;
}
int private_owned_id(const char *owner, const struct stat *ns, __u32 id, bool program)
{
	char path[128], *end;
	struct stat st;
	struct dirent *entry;
	unsigned long pid;
	DIR *dir;
	int result = -ENOENT;
	if (!owner[0] || strspn(owner, "0123456789") != strlen(owner)) return -EINVAL;
	errno = 0; pid = strtoul(owner, &end, 10);
	if (errno || *end || !pid || pid > INT_MAX) return -EINVAL;
	snprintf(path, sizeof(path), "/proc/%lu/ns/net", pid);
	if (stat(path, &st)) return -errno;
	if (st.st_dev != ns->st_dev || st.st_ino != ns->st_ino) return -EPERM;
	snprintf(path, sizeof(path), "/proc/%lu/fdinfo", pid);
	dir = opendir(path);
	if (!dir) return -errno;
	while ((entry = readdir(dir))) {
		char line[256];
		FILE *f;
		unsigned int found;
		if (entry->d_name[0] == '.') continue;
		snprintf(path, sizeof(path), "/proc/%lu/fdinfo/%.32s", pid, entry->d_name);
		f = fopen(path, "re");
		if (!f) continue;
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, program ? "prog_id:\t%u" : "map_id:\t%u", &found) == 1 && found == id) {
				result = 0; break;
			}
		}
		fclose(f);
		if (!result) break;
	}
	closedir(dir);
	return result;
}
