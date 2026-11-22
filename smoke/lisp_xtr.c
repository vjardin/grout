// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin <vjardin@free.fr>, Free Mobile

// Minimal LISP tunnel router (RFC 9300 data plane) for the smoke tests.
//
// capture  Decode the LISP packets received on an interface, one per line.
// send     Encapsulate UDP datagrams and send them to an RLOC.
// udp      Send plain UDP datagrams, one flow per datagram.
// recv     Report the plain UDP datagrams received on a port, one per line.

#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LISP_DATA_PORT 4341
#define LISP_F_I 0x08
#define LISP_IID_SHIFT 8
#define LISP_LSB_MASK ((1 << LISP_IID_SHIFT) - 1)

#define IP6_VERSION 6
#define IP6_VERSION_SHIFT 28
#define IP6_TC_SHIFT 20
#define IP6_FLOW_MASK ((1 << IP6_TC_SHIFT) - 1)

#define IP_VERSION_ANY UINT8_MAX
#define DEFAULT_PORT 7777
#define DEFAULT_TIMEOUT_S 5
#define DEFAULT_PAYLOAD "lisp"
#define DEFAULT_UNTIL "end"
#define MS_PER_S 1000
#define NS_PER_MS 1000000
#define WORD_MAX 32
#define RECV_CMSGS 2 // TTL and TOS
#define ARRAY_DIM(a) (sizeof(a) / sizeof(a[0]))

struct lisp_hdr {
	uint8_t flags;
	uint8_t nonce[3];
	uint32_t iid_lsb;
} __attribute__((packed));

struct ip_info {
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	size_t hdr_len;
	uint32_t flow;
	uint16_t len;
	uint8_t version;
	uint8_t proto;
	uint8_t tos;
	uint8_t ttl;
	bool cksum_ok;
	bool frag;
	bool df;
};

static uint32_t sum16(const void *data, size_t len, uint32_t sum) {
	const uint8_t *p = data;

	for (; len > 1; len -= 2, p += 2)
		sum += (p[0] << CHAR_BIT) | p[1];
	if (len > 0)
		sum += p[0] << CHAR_BIT;

	return sum;
}

static uint16_t fold(uint32_t sum) {
	while (sum > UINT16_MAX)
		sum = (sum & UINT16_MAX) + (sum >> (sizeof(uint16_t) * CHAR_BIT));
	return htons(~sum);
}

// First word of a payload, made printable.
static const char *text(const uint8_t *data, size_t len) {
	static char word[WORD_MAX + 1];
	size_t n;

	for (n = 0; n < len && n < WORD_MAX && data[n] != ' '; n++)
		word[n] = isgraph(data[n]) ? data[n] : '.';
	word[n] = '\0';

	return n > 0 ? word : "-";
}

static int64_t now_ms(void) {
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * MS_PER_S + ts.tv_nsec / NS_PER_MS;
}

static void touch(const char *path) {
	FILE *f;

	if (path == NULL)
		return;
	if ((f = fopen(path, "w")) == NULL)
		err(EXIT_FAILURE, "%s", path);
	fclose(f);
}

static unsigned long num(const char *arg) {
	unsigned long value;
	char *end;

	value = strtoul(arg, &end, 0);
	if (*arg == '\0' || *end != '\0')
		errx(EXIT_FAILURE, "invalid number: %s", arg);

	return value;
}

// Numeric address of a host, or wildcard address of a family when host is NULL.
static socklen_t
resolve(int family, const char *host, uint16_t port, struct sockaddr_storage *addr) {
	const struct addrinfo hints = {
		.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE,
		.ai_family = family,
		.ai_socktype = SOCK_DGRAM,
	};
	char service[NI_MAXSERV];
	struct addrinfo *res;
	socklen_t len;
	int ret;

	snprintf(service, sizeof(service), "%u", port);
	if ((ret = getaddrinfo(host, service, &hints, &res)) != 0)
		errx(EXIT_FAILURE, "%s: %s", host ?: "*", gai_strerror(ret));
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	len = res->ai_addrlen;
	freeaddrinfo(res);

	return len;
}

static void set_opt(int fd, int level, int opt, int value) {
	if (setsockopt(fd, level, opt, &value, sizeof(value)) < 0)
		err(EXIT_FAILURE, "setsockopt(%d, %d)", level, opt);
}

static void set_tos_ttl(int fd, int family, uint8_t tos, uint8_t ttl) {
	if (family == AF_INET) {
		set_opt(fd, IPPROTO_IP, IP_TOS, tos);
		set_opt(fd, IPPROTO_IP, IP_TTL, ttl);
	} else {
		set_opt(fd, IPPROTO_IPV6, IPV6_TCLASS, tos);
		set_opt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl);
	}
}

static bool parse_ip(const uint8_t *pkt, size_t len, struct ip_info *info) {
	struct ip6_hdr ip6;
	struct iphdr ip;
	uint32_t flow;
	uint16_t frag;

	memset(info, 0, sizeof(*info));
	if (len < sizeof(ip))
		return false;
	memcpy(&ip, pkt, sizeof(ip));
	info->version = ip.version;

	if (ip.version == IPVERSION) {
		info->hdr_len = ip.ihl * sizeof(uint32_t);
		if (info->hdr_len < sizeof(ip) || info->hdr_len > len)
			return false;
		frag = ntohs(ip.frag_off);
		inet_ntop(AF_INET, &ip.saddr, info->src, sizeof(info->src));
		inet_ntop(AF_INET, &ip.daddr, info->dst, sizeof(info->dst));
		info->tos = ip.tos;
		info->ttl = ip.ttl;
		info->len = ntohs(ip.tot_len);
		info->proto = ip.protocol;
		info->df = frag & IP_DF;
		info->frag = frag & (IP_MF | IP_OFFMASK);
		info->cksum_ok = fold(sum16(pkt, info->hdr_len, 0)) == 0;
		return true;
	}
	if (ip.version == IP6_VERSION && len >= sizeof(ip6)) {
		memcpy(&ip6, pkt, sizeof(ip6));
		flow = ntohl(ip6.ip6_flow);
		inet_ntop(AF_INET6, &ip6.ip6_src, info->src, sizeof(info->src));
		inet_ntop(AF_INET6, &ip6.ip6_dst, info->dst, sizeof(info->dst));
		info->hdr_len = sizeof(ip6);
		info->tos = flow >> IP6_TC_SHIFT;
		info->ttl = ip6.ip6_hlim;
		info->len = ntohs(ip6.ip6_plen) + sizeof(ip6);
		info->proto = ip6.ip6_nxt;
		info->flow = flow & IP6_FLOW_MASK;
		return true;
	}

	return false;
}

static void print_ip(const char *prefix, const struct ip_info *info) {
	printf("%saf=%u %ssrc=%s %sdst=%s",
	       prefix,
	       info->version,
	       prefix,
	       info->src,
	       prefix,
	       info->dst);
	printf(" %stos=0x%02x %sttl=%u %slen=%u",
	       prefix,
	       info->tos,
	       prefix,
	       info->ttl,
	       prefix,
	       info->len);
	if (info->version == IPVERSION) {
		printf(" %sdf=%d %sfrag=%d", prefix, info->df, prefix, info->frag);
		printf(" %scksum=%s", prefix, info->cksum_ok ? "ok" : "bad");
	} else {
		printf(" %sflow=0x%05x", prefix, info->flow);
	}
}

// Print the fields of an Ethernet frame if it holds a LISP data packet.
static bool decode_lisp(const uint8_t *frame, size_t len) {
	struct ip_info outer, inner;
	struct ether_header eth;
	struct lisp_hdr lisp;
	struct udphdr udp;
	uint32_t iid_lsb;

	if (len < sizeof(eth))
		return false;
	memcpy(&eth, frame, sizeof(eth));
	if (eth.ether_type != htons(ETHERTYPE_IP) && eth.ether_type != htons(ETHERTYPE_IPV6))
		return false;
	frame += sizeof(eth);
	len -= sizeof(eth);

	if (!parse_ip(frame, len, &outer) || outer.proto != IPPROTO_UDP || outer.frag)
		return false;
	// Ethernet padding is not part of the packet.
	if (outer.len < len)
		len = outer.len;
	if (len < outer.hdr_len + sizeof(udp) + sizeof(lisp))
		return false;
	frame += outer.hdr_len;
	len -= outer.hdr_len;

	memcpy(&udp, frame, sizeof(udp));
	if (udp.dest != htons(LISP_DATA_PORT))
		return false;
	memcpy(&lisp, frame + sizeof(udp), sizeof(lisp));
	iid_lsb = ntohl(lisp.iid_lsb);
	frame += sizeof(udp) + sizeof(lisp);
	len -= sizeof(udp) + sizeof(lisp);

	print_ip("", &outer);
	printf(" sport=%u udplen=%u udpcksum=0x%04x",
	       ntohs(udp.source),
	       ntohs(udp.len),
	       ntohs(udp.check));
	printf(" flags=0x%02x nonce=0x%02x%02x%02x",
	       lisp.flags,
	       lisp.nonce[0],
	       lisp.nonce[1],
	       lisp.nonce[2]);
	printf(" iid=%u lsb=0x%02x", iid_lsb >> LISP_IID_SHIFT, iid_lsb & LISP_LSB_MASK);

	if (len > 0 && !parse_ip(frame, len, &inner)) {
		printf(" iaf=unknown-%u", inner.version);
	} else if (len > 0) {
		printf(" ");
		print_ip("i", &inner);
		frame += inner.hdr_len;
		len -= inner.hdr_len;
		if (inner.proto == IPPROTO_UDP && len >= sizeof(udp)) {
			memcpy(&udp, frame, sizeof(udp));
			printf(" isport=%u idport=%u", ntohs(udp.source), ntohs(udp.dest));
			printf(" payload=%s", text(frame + sizeof(udp), len - sizeof(udp)));
		} else {
			printf(" iproto=%u", inner.proto);
		}
	}
	printf("\n");
	fflush(stdout);

	return true;
}

enum {
	OPT_COUNT = 1,
	OPT_TIMEOUT,
	OPT_READY,
	OPT_UNTIL,
	OPT_LOCAL,
	OPT_SPORT,
	OPT_DPORT,
	OPT_PORT,
	OPT_TOS,
	OPT_TTL,
	OPT_UDP_CKSUM,
	OPT_FLAGS,
	OPT_NONCE,
	OPT_IID,
	OPT_LSB,
	OPT_ISRC,
	OPT_IDST,
	OPT_ISPORT,
	OPT_IDPORT,
	OPT_ITOS,
	OPT_ITTL,
	OPT_INNER_VERSION,
	OPT_BAD_INNER_CKSUM,
	OPT_TRUNCATE,
	OPT_PAYLOAD,
	OPT_SIZE,
	OPT_DF,
	OPT_MAX,
};

static const struct option options[] = {
	{"count", required_argument, NULL, OPT_COUNT},
	{"timeout", required_argument, NULL, OPT_TIMEOUT},
	{"ready", required_argument, NULL, OPT_READY},
	{"until", required_argument, NULL, OPT_UNTIL},
	{"local", required_argument, NULL, OPT_LOCAL},
	{"sport", required_argument, NULL, OPT_SPORT},
	{"dport", required_argument, NULL, OPT_DPORT},
	{"port", required_argument, NULL, OPT_PORT},
	{"tos", required_argument, NULL, OPT_TOS},
	{"ttl", required_argument, NULL, OPT_TTL},
	{"udp-cksum", no_argument, NULL, OPT_UDP_CKSUM},
	{"flags", required_argument, NULL, OPT_FLAGS},
	{"nonce", required_argument, NULL, OPT_NONCE},
	{"iid", required_argument, NULL, OPT_IID},
	{"lsb", required_argument, NULL, OPT_LSB},
	{"isrc", required_argument, NULL, OPT_ISRC},
	{"idst", required_argument, NULL, OPT_IDST},
	{"isport", required_argument, NULL, OPT_ISPORT},
	{"idport", required_argument, NULL, OPT_IDPORT},
	{"itos", required_argument, NULL, OPT_ITOS},
	{"ittl", required_argument, NULL, OPT_ITTL},
	{"inner-version", required_argument, NULL, OPT_INNER_VERSION},
	{"bad-inner-cksum", no_argument, NULL, OPT_BAD_INNER_CKSUM},
	{"truncate", required_argument, NULL, OPT_TRUNCATE},
	{"payload", required_argument, NULL, OPT_PAYLOAD},
	{"size", required_argument, NULL, OPT_SIZE},
	{"df", no_argument, NULL, OPT_DF},
	{NULL, 0, NULL, 0},
};

// Value of each option. The inner destinations may be given several times.
static const char *args[OPT_MAX];
static const char **inner_dst;
static unsigned n_inner_dst;

static unsigned long arg_num(int opt, unsigned long def) {
	return args[opt] != NULL ? num(args[opt]) : def;
}

static const char *arg_str(int opt, const char *def) {
	return args[opt] ?: def;
}

static int cmd_capture(const char *ifname) {
	int64_t deadline = now_ms() + arg_num(OPT_TIMEOUT, DEFAULT_TIMEOUT_S) * MS_PER_S;
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	unsigned long count = arg_num(OPT_COUNT, 1), seen = 0;
	static uint8_t frame[UINT16_MAX];
	socklen_t sll_len = sizeof(sll);
	struct pollfd pfd;
	int64_t left;
	ssize_t len;

	if ((sll.sll_ifindex = if_nametoindex(ifname)) == 0)
		err(EXIT_FAILURE, "%s", ifname);
	if ((pfd.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		err(EXIT_FAILURE, "socket");
	if (bind(pfd.fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		err(EXIT_FAILURE, "bind");
	pfd.events = POLLIN;
	touch(args[OPT_READY]);

	while (seen < count && (left = deadline - now_ms()) > 0) {
		if (poll(&pfd, 1, left) <= 0)
			break;
		len = recvfrom(pfd.fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, &sll_len);
		if (len < 0)
			err(EXIT_FAILURE, "recvfrom");
		if (sll.sll_pkttype != PACKET_OUTGOING && decode_lisp(frame, len))
			seen++;
	}
	if (seen < count)
		errx(EXIT_FAILURE, "%lu of %lu LISP packets received", seen, count);

	return EXIT_SUCCESS;
}

struct inner {
	const char *payload;
	const char *src;
	uint8_t version;
	uint16_t sport;
	uint16_t dport;
	uint8_t tos;
	uint8_t ttl;
	bool bad_cksum;
};

// Build an IP packet that holds a UDP datagram. Return its length.
static size_t build_inner(uint8_t *buf, const struct inner *in, const char *dst) {
	size_t payload_len = strlen(in->payload);
	uint16_t udp_len = sizeof(struct udphdr) + payload_len;
	struct udphdr udp = {
		.source = htons(in->sport),
		.dest = htons(in->dport),
		.len = htons(udp_len),
	};
	struct in6_addr src6, dst6;
	struct in_addr src4, dst4;
	struct ip6_hdr ip6 = {0};
	struct iphdr ip = {0};
	size_t hdr_len;
	uint32_t sum;

	sum = sum16(in->payload, payload_len, IPPROTO_UDP + udp_len);
	sum = sum16(&udp, sizeof(udp), sum);

	if (inet_pton(AF_INET, in->src, &src4) == 1 && inet_pton(AF_INET, dst, &dst4) == 1) {
		sum = sum16(&src4, sizeof(src4), sum);
		sum = sum16(&dst4, sizeof(dst4), sum);
		ip.version = IPVERSION;
		ip.ihl = sizeof(ip) / sizeof(uint32_t);
		ip.tos = in->tos;
		ip.tot_len = htons(sizeof(ip) + udp_len);
		ip.ttl = in->ttl;
		ip.protocol = IPPROTO_UDP;
		ip.saddr = src4.s_addr;
		ip.daddr = dst4.s_addr;
		ip.check = fold(sum16(&ip, sizeof(ip), 0));
		if (in->bad_cksum)
			ip.check = ~ip.check;
		hdr_len = sizeof(ip);
		memcpy(buf, &ip, hdr_len);
	} else if (
		inet_pton(AF_INET6, in->src, &src6) == 1 && inet_pton(AF_INET6, dst, &dst6) == 1
	) {
		sum = sum16(&src6, sizeof(src6), sum);
		sum = sum16(&dst6, sizeof(dst6), sum);
		ip6.ip6_flow = htonl(
			(IP6_VERSION << IP6_VERSION_SHIFT) | (in->tos << IP6_TC_SHIFT)
		);
		ip6.ip6_plen = htons(udp_len);
		ip6.ip6_nxt = IPPROTO_UDP;
		ip6.ip6_hlim = in->ttl;
		ip6.ip6_src = src6;
		ip6.ip6_dst = dst6;
		hdr_len = sizeof(ip6);
		memcpy(buf, &ip6, hdr_len);
	} else {
		errx(EXIT_FAILURE, "invalid inner addresses: %s %s", in->src, dst);
	}
	udp.check = fold(sum) ?: UINT16_MAX;
	memcpy(buf + hdr_len, &udp, sizeof(udp));
	memcpy(buf + hdr_len + sizeof(udp), in->payload, payload_len);

	if (in->version != IP_VERSION_ANY) {
		memcpy(&ip, buf, sizeof(ip));
		ip.version = in->version;
		memcpy(buf, &ip, sizeof(ip));
	}

	return hdr_len + udp_len;
}

static int cmd_send(const char *rloc_name) {
	const struct inner in = {
		.payload = arg_str(OPT_PAYLOAD, DEFAULT_PAYLOAD),
		.src = args[OPT_ISRC],
		.version = arg_num(OPT_INNER_VERSION, IP_VERSION_ANY),
		.sport = arg_num(OPT_ISPORT, DEFAULT_PORT),
		.dport = arg_num(OPT_IDPORT, DEFAULT_PORT),
		.tos = arg_num(OPT_ITOS, 0),
		.ttl = arg_num(OPT_ITTL, IPDEFTTL),
		.bad_cksum = args[OPT_BAD_INNER_CKSUM] != NULL,
	};
	uint32_t iid_lsb = (arg_num(OPT_IID, 0) << LISP_IID_SHIFT) | arg_num(OPT_LSB, 0);
	struct lisp_hdr lisp = {
		.flags = arg_num(OPT_FLAGS, LISP_F_I),
		.iid_lsb = htonl(iid_lsb),
	};
	size_t truncate = arg_num(OPT_TRUNCATE, UINT16_MAX);
	uint32_t nonce = arg_num(OPT_NONCE, 0);
	struct sockaddr_storage rloc, src;
	static uint8_t pkt[UINT16_MAX];
	socklen_t rloc_len, src_len;
	size_t len;
	int fd;

	if (in.src == NULL || n_inner_dst == 0)
		errx(EXIT_FAILURE, "send: --isrc and --idst are required");
	// The largest headers that are built in front of the payload.
	if (strlen(in.payload)
	    > sizeof(pkt) - sizeof(lisp) - sizeof(struct ip6_hdr) - sizeof(struct udphdr))
		errx(EXIT_FAILURE, "send: payload too large");

	rloc_len = resolve(AF_UNSPEC, rloc_name, arg_num(OPT_DPORT, LISP_DATA_PORT), &rloc);
	if ((fd = socket(rloc.ss_family, SOCK_DGRAM, 0)) < 0)
		err(EXIT_FAILURE, "socket");
	set_tos_ttl(fd, rloc.ss_family, arg_num(OPT_TOS, 0), arg_num(OPT_TTL, IPDEFTTL));
	if (args[OPT_UDP_CKSUM] == NULL && rloc.ss_family == AF_INET)
		set_opt(fd, SOL_SOCKET, SO_NO_CHECK, true);
	else if (args[OPT_UDP_CKSUM] == NULL)
		set_opt(fd, IPPROTO_UDP, UDP_NO_CHECK6_TX, true);
	if (args[OPT_LOCAL] != NULL || args[OPT_SPORT] != NULL) {
		src_len = resolve(rloc.ss_family, args[OPT_LOCAL], arg_num(OPT_SPORT, 0), &src);
		if (bind(fd, (struct sockaddr *)&src, src_len) < 0)
			err(EXIT_FAILURE, "bind");
	}

	for (unsigned i = 0; i < sizeof(lisp.nonce); i++)
		lisp.nonce[i] = nonce >> ((sizeof(lisp.nonce) - 1 - i) * CHAR_BIT);
	memcpy(pkt, &lisp, sizeof(lisp));

	for (unsigned i = 0; i < n_inner_dst; i++) {
		len = sizeof(lisp) + build_inner(pkt + sizeof(lisp), &in, inner_dst[i]);
		if (len > truncate)
			len = truncate;
		if (sendto(fd, pkt, len, 0, (struct sockaddr *)&rloc, rloc_len) < 0)
			err(EXIT_FAILURE, "sendto");
	}
	close(fd);

	return EXIT_SUCCESS;
}

static int cmd_udp(const char *dst_name) {
	int pmtudisc = args[OPT_DF] != NULL ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
	const char *payload = arg_str(OPT_PAYLOAD, DEFAULT_PAYLOAD);
	size_t len = strlen(payload), size = arg_num(OPT_SIZE, 0);
	unsigned long count = arg_num(OPT_COUNT, 1);
	struct sockaddr_storage dst, src;
	static char data[UINT16_MAX];
	socklen_t dst_len, src_len;
	int fd;

	// The payload starts with a word, padded up to the requested size.
	if (len >= sizeof(data) || size > sizeof(data))
		errx(EXIT_FAILURE, "udp: payload too large");
	memset(data, 'x', sizeof(data));
	memcpy(data, payload, len);
	if (size > len)
		data[len] = ' ';
	else
		size = len;

	dst_len = resolve(AF_UNSPEC, dst_name, arg_num(OPT_PORT, DEFAULT_PORT), &dst);
	for (unsigned long i = 0; i < count; i++) {
		if ((fd = socket(dst.ss_family, SOCK_DGRAM, 0)) < 0)
			err(EXIT_FAILURE, "socket");
		set_tos_ttl(fd, dst.ss_family, arg_num(OPT_TOS, 0), arg_num(OPT_TTL, IPDEFTTL));
		if (dst.ss_family == AF_INET)
			set_opt(fd, IPPROTO_IP, IP_MTU_DISCOVER, pmtudisc);
		if (args[OPT_SPORT] != NULL) {
			src_len = resolve(dst.ss_family, NULL, arg_num(OPT_SPORT, 0) + i, &src);
			if (bind(fd, (struct sockaddr *)&src, src_len) < 0)
				err(EXIT_FAILURE, "bind");
		}
		if (sendto(fd, data, size, 0, (struct sockaddr *)&dst, dst_len) < 0)
			err(EXIT_FAILURE, "sendto");
		close(fd);
	}

	return EXIT_SUCCESS;
}

// Report a datagram along with the TTL and the TOS it was received with.
static const char *recv_one(int fd) {
	char control[CMSG_SPACE(sizeof(int)) * RECV_CMSGS];
	static uint8_t data[UINT16_MAX];
	char host[INET6_ADDRSTRLEN];
	struct sockaddr_storage src;
	char service[NI_MAXSERV];
	struct iovec iov = {
		.iov_base = data,
		.iov_len = sizeof(data),
	};
	struct msghdr msg = {
		.msg_name = &src,
		.msg_namelen = sizeof(src),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	int ttl = 0, tos = 0;
	const char *word;
	ssize_t len;

	if ((len = recvmsg(fd, &msg, 0)) < 0)
		err(EXIT_FAILURE, "recvmsg");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
			memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
		else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
			tos = *(uint8_t *)CMSG_DATA(cmsg);
		else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
			memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
		else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS)
			memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
	}

	getnameinfo(
		(struct sockaddr *)&src,
		msg.msg_namelen,
		host,
		sizeof(host),
		service,
		sizeof(service),
		NI_NUMERICHOST | NI_NUMERICSERV
	);
	word = text(data, len);
	printf("af=%u src=%s sport=%s",
	       src.ss_family == AF_INET ? IPVERSION : IP6_VERSION,
	       host,
	       service);
	printf(" tos=0x%02x ttl=%d size=%zd payload=%s\n", tos, ttl, len, word);
	fflush(stdout);

	return word;
}

static int cmd_recv(void) {
	int64_t deadline = now_ms() + arg_num(OPT_TIMEOUT, 2 * DEFAULT_TIMEOUT_S) * MS_PER_S;
	const char *until = arg_str(OPT_UNTIL, DEFAULT_UNTIL);
	uint16_t port = arg_num(OPT_PORT, DEFAULT_PORT);
	const int families[] = {AF_INET, AF_INET6};
	struct pollfd pfd[ARRAY_DIM(families)];
	struct sockaddr_storage addr;
	socklen_t addr_len;
	bool done = false;
	int64_t left;

	for (unsigned i = 0; i < ARRAY_DIM(families); i++) {
		if ((pfd[i].fd = socket(families[i], SOCK_DGRAM, 0)) < 0)
			err(EXIT_FAILURE, "socket");
		pfd[i].events = POLLIN;
		if (families[i] == AF_INET) {
			set_opt(pfd[i].fd, IPPROTO_IP, IP_RECVTTL, true);
			set_opt(pfd[i].fd, IPPROTO_IP, IP_RECVTOS, true);
		} else {
			set_opt(pfd[i].fd, IPPROTO_IPV6, IPV6_V6ONLY, true);
			set_opt(pfd[i].fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, true);
			set_opt(pfd[i].fd, IPPROTO_IPV6, IPV6_RECVTCLASS, true);
		}
		addr_len = resolve(families[i], NULL, port, &addr);
		if (bind(pfd[i].fd, (struct sockaddr *)&addr, addr_len) < 0)
			err(EXIT_FAILURE, "bind");
	}
	touch(args[OPT_READY]);

	while (!done) {
		left = deadline - now_ms();
		if (left <= 0 || poll(pfd, ARRAY_DIM(pfd), left) <= 0)
			errx(EXIT_FAILURE, "%s not received", until);
		for (unsigned i = 0; i < ARRAY_DIM(pfd); i++) {
			if (pfd[i].revents & POLLIN && strcmp(recv_one(pfd[i].fd), until) == 0)
				done = true;
		}
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	const char *cmd = argc > 1 ? argv[1] : "";
	const char *target;
	int opt;

	if ((inner_dst = calloc(argc, sizeof(*inner_dst))) == NULL)
		err(EXIT_FAILURE, "calloc");
	while ((opt = getopt_long(argc - 1, argv + 1, "", options, NULL)) != -1) {
		if (opt == '?')
			return EXIT_FAILURE;
		if (opt == OPT_IDST)
			inner_dst[n_inner_dst++] = optarg;
		args[opt] = optarg ?: "";
	}
	target = optind + 1 < argc ? argv[optind + 1] : NULL;

	if (strcmp(cmd, "recv") == 0)
		return cmd_recv();
	if (target != NULL && strcmp(cmd, "capture") == 0)
		return cmd_capture(target);
	if (target != NULL && strcmp(cmd, "send") == 0)
		return cmd_send(target);
	if (target != NULL && strcmp(cmd, "udp") == 0)
		return cmd_udp(target);

	fprintf(stderr, "usage: %s capture IFACE|send RLOC|udp DST|recv [OPTIONS]\n", argv[0]);
	return EXIT_FAILURE;
}
