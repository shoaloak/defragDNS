#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h> /* for struct ethhdr   */
#include <linux/ip.h>       /* for struct iphdr    */
#include <linux/ipv6.h>     /* for struct ipv6hdr  */
#include <linux/in.h>       /* for IPPROTO_UDP     */
#include <linux/udp.h>      /* for struct udphdr   */
#include <linux/pkt_cls.h>
#include <bpf_helpers.h>

#define DNS_PORT 53
#define MAX_LABELS 50

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# ifndef  ntohs
#  define ntohs(x) __builtin_bswap16(x)
# endif
# ifndef  htons
#  define htons(x) __builtin_bswap16(x)
# endif
# ifndef  ntohl
#  define ntohl(x) __builtin_bswap32(x)
# endif
# ifndef  htonl
#  define htonl(x) __builtin_bswap32(x)
# endif
#else
# ifndef  ntohs
#  define ntohs(x) (x)
# endif
# ifndef  htons
#  define htons(x) (x)
# endif
# ifndef  ntohl
#  define ntohl(x) (x)
# endif
# ifndef  htonl
#  define htonl(x) (x)
# endif
#endif

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif


struct vlanhdr {
	uint16_t tci;
	uint16_t encap_proto;
};

struct dnshdr {
	uint16_t id;

	uint8_t  rd     : 1;
	uint8_t  tc     : 1;
	uint8_t  aa     : 1;
	uint8_t  opcode : 4;
	uint8_t  qr     : 1;

	uint8_t  rcode  : 4;
	uint8_t  cd     : 1;
	uint8_t  ad     : 1;
	uint8_t  z      : 1;
	uint8_t  ra     : 1;

	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

struct cursor {
	void *pos;
	void *end;
};

static __inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

static __inline
void cursor_init_skb(struct cursor *c, struct __sk_buff *skb)
{
	c->end = (void *)(long)skb->data_end;
	c->pos = (void *)(long)skb->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __inline						\
struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							\
	struct STRUCT *ret = c->pos;			\
	if (c->pos + sizeof(struct STRUCT) > c->end)	\
		return 0;				\
	c->pos += sizeof(struct STRUCT);		\
	return ret;					\
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)

static __inline
struct ethhdr *parse_eth(struct cursor *c, uint16_t *eth_proto)
{
	struct ethhdr  *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;
       
	*eth_proto = eth->h_proto;
	if (*eth_proto == htons(ETH_P_8021Q)
	||  *eth_proto == htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == htons(ETH_P_8021Q)
		||  *eth_proto == htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

static __inline
void update_checksum(uint16_t *csum, uint16_t old_val, uint16_t new_val)
{
	uint32_t new_csum_value;
	uint32_t new_csum_comp;
	uint32_t undo;

	undo = ~((uint32_t)*csum) + ~((uint32_t)old_val);
	new_csum_value = undo + (undo < ~((uint32_t)old_val)) + (uint32_t)new_val;
	new_csum_comp = new_csum_value + (new_csum_value < ((uint32_t)new_val));
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
	*csum = (uint16_t)~new_csum_comp;
}

static __inline
void rewrite_qname4(struct cursor *c, uint8_t *pkt, struct udphdr *udp)
{
	uint8_t *labels[MAX_LABELS];
	uint8_t  i;

	for (i = 0; i < MAX_LABELS; i++) { /* Maximum 128 labels */
		uint8_t o;

		if (c->pos + 1 > c->end)
			return;

	       	o = *(uint8_t *)c->pos;
		if ((o & 0xC0) == 0xC0) {
			return;

		} else if (o & 0xC0)
			/* Unknown label type */
			return;

		labels[i] = c->pos;
		c->pos += o + 1;
		if (!o)
			break;
	}
	if (i >= MAX_LABELS || i < 5
	|| *labels[i-4] != 10
	||  labels[i-4] + *labels[i-4] + 2 > (uint8_t *)c->end
	||  labels[i-4][ 1] <  '0' || labels[i-4][1] >  '9'
	||  labels[i-4][ 2] <  '0' || labels[i-4][2] >  '9'
	||  labels[i-4][ 3] <  '0' || labels[i-4][3] >  '9'
	||  labels[i-4][ 4] <  '0' || labels[i-4][4] >  '9'
	||  labels[i-4][ 5] != '-'
	|| (labels[i-4][ 6] != 'p' && labels[i-4][6] != 'P')
	|| (labels[i-4][ 7] != 'l' && labels[i-4][7] != 'L')
	|| (labels[i-4][ 8] != 'u' && labels[i-4][8] != 'U')
	|| (labels[i-4][ 9] != 's' && labels[i-4][9] != 'S')
	||  labels[i-4][10] != '0' )
		return;

	/* Change aligned on 16 bits for checksum recalculaction */
	uint16_t *pls_pos = (labels[i-4] + 10 - (uint8_t *)udp) % 2
			  ? (uint16_t *)&labels[i-4][9]
			  : (uint16_t *)&labels[i-4][10];
	uint16_t  old_pls = *pls_pos;

	switch (*labels[i-5]) {
	case 39: labels[i-4][10] = '2'; break;
	case 38: labels[i-4][10] = '4'; break;
	case 37: labels[i-4][10] = '6'; break;
	case 36: labels[i-4][10] = '8'; break;
	case 35: labels[i-4][10] = 'a'; break;
	case 34: labels[i-4][10] = 'c'; break;
	default: break;
	}
	update_checksum(&udp->check, old_pls, *pls_pos);
#if MTU4 != 1500
	if (labels[i-4][1] != '1' || labels[i-4][2] != '5'
	||  labels[i-4][3] != '0' || labels[i-4][4] != '0')
		return;

	if ((labels[i-4] - (uint8_t *)udp) % 2) {
		uint16_t *sh1_pos = (uint16_t*)&labels[i-4][1];
		uint16_t  old_sh1 = *sh1_pos;
		uint16_t *sh2_pos = (uint16_t*)&labels[i-4][3];
		uint16_t  old_sh2 = *sh2_pos;

		labels[i-4][1] =  MTU4_STR[0];
		labels[i-4][2] =  MTU4_STR[1];
		labels[i-4][3] =  MTU4_STR[2];
		labels[i-4][4] =  MTU4_STR[3];

		update_checksum(&udp->check, old_sh1,*sh1_pos);
		update_checksum(&udp->check, old_sh2,*sh2_pos);
	} else {
		uint16_t *sh1_pos = (uint16_t*)&labels[i-4][0];
		uint16_t  old_sh1 = *sh1_pos;
		uint16_t *sh2_pos = (uint16_t*)&labels[i-4][2];
		uint16_t  old_sh2 = *sh2_pos;
		uint16_t *sh3_pos = (uint16_t*)&labels[i-4][4];
		uint16_t  old_sh3 = *sh3_pos;

		labels[i-4][1] =  MTU4_STR[0];
		labels[i-4][2] =  MTU4_STR[1];
		labels[i-4][3] =  MTU4_STR[2];
		labels[i-4][4] =  MTU4_STR[3];

		update_checksum(&udp->check, old_sh1,*sh1_pos);
		update_checksum(&udp->check, old_sh2,*sh2_pos);
		update_checksum(&udp->check, old_sh3,*sh3_pos);
	}
#endif
}

static __inline
void restore_qname4(struct cursor *c, uint8_t *pkt, struct udphdr *udp)
{
	uint8_t *labels[MAX_LABELS];
	uint8_t  i;

	for (i = 0; i < MAX_LABELS; i++) { /* Maximum 128 labels */
		uint8_t o;

		if (c->pos + 1 > c->end)
			return;

	       	o = *(uint8_t *)c->pos;
		if ((o & 0xC0) == 0xC0) {
			return;

		} else if (o & 0xC0)
			/* Unknown label type */
			return;

		labels[i] = c->pos;
		c->pos += o + 1;
		if (!o)
			break;
	}
	if (i >= MAX_LABELS || i < 5
	|| *labels[i-4] != 10
	||  labels[i-4] + *labels[i-4] + 2 >  (uint8_t *)c->end
	||  labels[i-4][ 1] <  '0' || labels[i-4][1] >  '9'
	||  labels[i-4][ 2] <  '0' || labels[i-4][2] >  '9'
	||  labels[i-4][ 3] <  '0' || labels[i-4][3] >  '9'
	||  labels[i-4][ 4] <  '0' || labels[i-4][4] >  '9'
	||  labels[i-4][ 5] != '-'
	|| (labels[i-4][ 6] != 'p' && labels[i-4][6] != 'P')
	|| (labels[i-4][ 7] != 'l' && labels[i-4][7] != 'L')
	|| (labels[i-4][ 8] != 'u' && labels[i-4][8] != 'U')
	|| (labels[i-4][ 9] != 's' && labels[i-4][9] != 'S'))
		return;

    if (labels[i-4][10] != '0') {
        /* Change aligned on 16 bits for checksum recalculaction
         * Doesn't work on TC/TX!  Maybe we should use bpf_l4_csum_replace()
         * and bpf_csum_diff().
         *
         * uint16_t *pls_pos = (labels[i-4] + 10 - (uint8_t *)udp) % 2
         * 		  ? (uint16_t *)&labels[i-4][9]
         * 		  : (uint16_t *)&labels[i-4][10];
         * uint16_t  old_pls = *pls_pos;
         */
        labels[i-4][10] = '0';
        udp->check = 0;
    }

#if MTU4 != 1500
	if (labels[i-4][1] != MTU4_STR[0] || labels[i-4][2] != MTU4_STR[1]
	||  labels[i-4][3] != MTU4_STR[2] || labels[i-4][4] != MTU4_STR[3])
		return;

	if ((labels[i-4] - (uint8_t *)udp) % 2) {
		/* TODO: 4 bytes checksum recalculating labes[i-4][1-4]
		 *       with bpf_l4_csum_replace() and bpf_csum_diff()
		 */
		labels[i-4][1] = '1';
		labels[i-4][2] = '5';
		labels[i-4][3] = '0';
		labels[i-4][4] = '0';
        udp->check = 0;
	} else {
		/* TODO: 6 bytes checksum recalculating labes[i-4][0-5]
		 *       with bpf_l4_csum_replace() and bpf_csum_diff()
		 */
		labels[i-4][1] = '1';
		labels[i-4][2] = '5';
		labels[i-4][3] = '0';
		labels[i-4][4] = '0';
        udp->check = 0;
	}
#endif
	return;
}

static __inline
void rewrite_qname6(struct cursor *c, uint8_t *pkt, struct udphdr *udp)
{
	uint8_t *labels[MAX_LABELS];
	uint8_t  i;

	for (i = 0; i < MAX_LABELS; i++) { /* Maximum 128 labels */
		uint8_t o;

		if (c->pos + 1 > c->end)
			return;

	       	o = *(uint8_t *)c->pos;
		if ((o & 0xC0) == 0xC0) {
			return;

		} else if (o & 0xC0)
			/* Unknown label type */
			return;

		labels[i] = c->pos;
		c->pos += o + 1;
		if (!o)
			break;
	}
	if (i >= MAX_LABELS || i < 5
	|| *labels[i-4] != 10
	||  labels[i-4] + *labels[i-4] + 2 > (uint8_t *)c->end
	||  labels[i-4][ 1] <  '0' || labels[i-4][1] >  '9'
	||  labels[i-4][ 2] <  '0' || labels[i-4][2] >  '9'
	||  labels[i-4][ 3] <  '0' || labels[i-4][3] >  '9'
	||  labels[i-4][ 4] <  '0' || labels[i-4][4] >  '9'
	||  labels[i-4][ 5] != '-'
	|| (labels[i-4][ 6] != 'p' && labels[i-4][6] != 'P')
	|| (labels[i-4][ 7] != 'l' && labels[i-4][7] != 'L')
	|| (labels[i-4][ 8] != 'u' && labels[i-4][8] != 'U')
	|| (labels[i-4][ 9] != 's' && labels[i-4][9] != 'S')
	||  labels[i-4][10] != '0' )
		return;

	/* Change aligned on 16 bits for checksum recalculaction */
	uint16_t *pls_pos = (labels[i-4] + 10 - (uint8_t *)udp) % 2
			  ? (uint16_t *)&labels[i-4][9]
			  : (uint16_t *)&labels[i-4][10];
	uint16_t  old_pls = *pls_pos;

	switch (*labels[i-5]) {
	case 39: labels[i-4][10] = '2'; break;
	case 38: labels[i-4][10] = '4'; break;
	case 37: labels[i-4][10] = '6'; break;
	case 36: labels[i-4][10] = '8'; break;
	case 35: labels[i-4][10] = 'a'; break;
	case 34: labels[i-4][10] = 'c'; break;
	default: break;
	}
	update_checksum(&udp->check, old_pls, *pls_pos);
#if MTU6 != 1500
	if (labels[i-4][1] != '1' || labels[i-4][2] != '5'
	||  labels[i-4][3] != '0' || labels[i-4][4] != '0')
		return;

	if ((labels[i-4] - (uint8_t *)udp) % 2) {
		uint16_t *sh1_pos = (uint16_t*)&labels[i-4][1];
		uint16_t  old_sh1 = *sh1_pos;
		uint16_t *sh2_pos = (uint16_t*)&labels[i-4][3];
		uint16_t  old_sh2 = *sh2_pos;

		labels[i-4][1] =  MTU6_STR[0];
		labels[i-4][2] =  MTU6_STR[1];
		labels[i-4][3] =  MTU6_STR[2];
		labels[i-4][4] =  MTU6_STR[3];

		update_checksum(&udp->check, old_sh1,*sh1_pos);
		update_checksum(&udp->check, old_sh2,*sh2_pos);
	} else {
		uint16_t *sh1_pos = (uint16_t*)&labels[i-4][0];
		uint16_t  old_sh1 = *sh1_pos;
		uint16_t *sh2_pos = (uint16_t*)&labels[i-4][2];
		uint16_t  old_sh2 = *sh2_pos;
		uint16_t *sh3_pos = (uint16_t*)&labels[i-4][4];
		uint16_t  old_sh3 = *sh3_pos;

		labels[i-4][1] =  MTU6_STR[0];
		labels[i-4][2] =  MTU6_STR[1];
		labels[i-4][3] =  MTU6_STR[2];
		labels[i-4][4] =  MTU6_STR[3];

		update_checksum(&udp->check, old_sh1,*sh1_pos);
		update_checksum(&udp->check, old_sh2,*sh2_pos);
		update_checksum(&udp->check, old_sh3,*sh3_pos);
	}
#endif
}

static __inline
uint16_t restore_qname6(struct cursor *c, uint8_t *pkt, struct udphdr *udp)
{
	uint8_t *labels[MAX_LABELS];
	uint8_t  i;

	for (i = 0; i < MAX_LABELS; i++) { /* Maximum 128 labels */
		uint8_t o;

		if (c->pos + 1 > c->end)
			return 0;

	       	o = *(uint8_t *)c->pos;
		if ((o & 0xC0) == 0xC0) {
			return 0;

		} else if (o & 0xC0)
			/* Unknown label type */
			return 0;

		labels[i] = c->pos;
		c->pos += o + 1;
		if (!o)
			break;
	}
	if (i >= MAX_LABELS || i < 5
	|| *labels[i-4] != 10
	||  labels[i-4] + *labels[i-4] + 2 >  (uint8_t *)c->end
	||  labels[i-4][ 1] <  '0' || labels[i-4][1] >  '9'
	||  labels[i-4][ 2] <  '0' || labels[i-4][2] >  '9'
	||  labels[i-4][ 3] <  '0' || labels[i-4][3] >  '9'
	||  labels[i-4][ 4] <  '0' || labels[i-4][4] >  '9'
	||  labels[i-4][ 5] != '-'
	|| (labels[i-4][ 6] != 'p' && labels[i-4][6] != 'P')
	|| (labels[i-4][ 7] != 'l' && labels[i-4][7] != 'L')
	|| (labels[i-4][ 8] != 'u' && labels[i-4][8] != 'U')
	|| (labels[i-4][ 9] != 's' && labels[i-4][9] != 'S'))
		return 0;

    if (labels[i-4][10] != '0') {
        if ((labels[i-4] - (uint8_t *)udp) % 2) {
            uint16_t old = ((uint16_t *)&labels[i-4][1])[4];
            labels[i-4][10] = '0';
#if MTU6 != 1280
            update_checksum(&udp->check, old, ((uint16_t *)&labels[i-4][1])[4]);
#endif
        } else {
            uint16_t old = ((uint16_t *)labels[i-4])[5];
            labels[i-4][10] = '0';
#if MTU6 != 1280
            update_checksum(&udp->check, old, ((uint16_t *)labels[i-4])[5]);
#endif
        }
    }

#if MTU6 != 1500
	if (labels[i-4][1] != MTU6_STR[0] || labels[i-4][2] != MTU6_STR[1]
	||  labels[i-4][3] != MTU6_STR[2] || labels[i-4][4] != MTU6_STR[3])
		return 0;

	if ((labels[i-4] - (uint8_t *)udp) % 2) {
        uint16_t old0 = ((uint16_t *)&labels[i-4][1])[0];
        uint16_t old1 = ((uint16_t *)&labels[i-4][1])[1];
		labels[i-4][1] = '1';
		labels[i-4][2] = '5';
		labels[i-4][3] = '0';
		labels[i-4][4] = '0';
#if MTU6 != 1280
		update_checksum(&udp->check, old0, ((uint16_t *)&labels[i-4][1])[0]);
		update_checksum(&udp->check, old1, ((uint16_t *)&labels[i-4][1])[1]);
#endif
	} else {
        uint16_t old0 = ((uint16_t *)labels[i-4])[0];
        uint16_t old1 = ((uint16_t *)labels[i-4])[1];
        uint16_t old2 = ((uint16_t *)labels[i-4])[2];
		labels[i-4][1] = '1';
		labels[i-4][2] = '5';
		labels[i-4][3] = '0';
		labels[i-4][4] = '0';
#if MTU6 != 1280
		update_checksum(&udp->check, old0, ((uint16_t *)labels[i-4])[0]);
		update_checksum(&udp->check, old1, ((uint16_t *)labels[i-4])[1]);
		update_checksum(&udp->check, old2, ((uint16_t *)labels[i-4])[2]);
#endif
	}
#endif
	return (labels[i-4] - (uint8_t *)pkt) + 1;
}


__section("xdp-rewrite-qname")
int xdp_rewrite_qname(struct xdp_md *ctx)
{
	struct cursor   c;
	uint16_t        eth_proto;
	struct iphdr   *ipv4;
	struct ipv6hdr *ipv6;
	struct udphdr  *udp;
	struct dnshdr  *dns;

	cursor_init(&c, ctx);
	if (!parse_eth(&c, &eth_proto))
		return XDP_PASS;

	if (eth_proto == htons(ETH_P_IP)) {
        if (!(ipv4 = parse_iphdr(&c)) || ipv4->protocol != IPPROTO_UDP
        ||  !(udp = parse_udphdr(&c)) || udp->dest != htons(DNS_PORT)
        ||  !(dns = parse_dnshdr(&c)))
            return XDP_PASS;

        rewrite_qname4(&c, (void *)dns, udp);

    } else if (eth_proto == htons(ETH_P_IPV6)) {
        if (!(ipv6 = parse_ipv6hdr(&c)) || ipv6->nexthdr != IPPROTO_UDP
        ||  !(udp = parse_udphdr(&c))   ||  udp->dest != htons(DNS_PORT)
        ||  !(dns = parse_dnshdr(&c)))
            return XDP_PASS;

        rewrite_qname6(&c, (void *)dns, udp);
    }
	return XDP_PASS;
}

__section("tc-restore-qname")
int tc_restore_qname(struct __sk_buff *skb)
{
	struct cursor   c;
	uint16_t        eth_proto;
	struct iphdr   *ipv4;
	struct ipv6hdr *ipv6;
	struct udphdr  *udp;
	struct dnshdr  *dns;

	cursor_init_skb(&c, skb);
	if (!parse_eth(&c, &eth_proto))
		return TC_ACT_OK;

	if (eth_proto == htons(ETH_P_IP)) {
        if (!(ipv4 = parse_iphdr(&c)) || ipv4->protocol != IPPROTO_UDP
        ||  !(udp = parse_udphdr(&c)) || udp->source != htons(DNS_PORT)
        ||  !(dns = parse_dnshdr(&c)))
            return TC_ACT_OK;

		uint16_t old_val = ipv4->frag_off;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		ipv4->frag_off |= 0x0040;
#else
		ipv4->frag_off |= 0x4000;
#endif
		update_checksum(&ipv4->check, old_val, ipv4->frag_off);
        restore_qname4(&c, (void *)dns, udp);

    } else if (eth_proto == htons(ETH_P_IPV6)) {
        if (!(ipv6 = parse_ipv6hdr(&c)) || ipv6->nexthdr  != IPPROTO_UDP
        ||  !(udp = parse_udphdr(&c))   || udp->source != htons(DNS_PORT)
        ||  !(dns = parse_dnshdr(&c)))
            return TC_ACT_OK;

        restore_qname6(&c, (void *)dns, udp);
    }
	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
