CC=clang
MTU=1500
MTU4=$(MTU)
MTU6=$(MTU)
CFLAGS=-O2 -Wall -Werror -Wno-unused -I ../libbpf/src -DMTU4=$(MTU4) -D'MTU4_STR="$(MTU4)"' -DMTU6=$(MTU6) -D'MTU6_STR="$(MTU6)"'

DEV=eth0

XDP_PROG=xdp_query_rewrite_kern.o

all: $(XDP_PROG)

$(XDP_PROG): xdp_query_rewrite_kern.c
	echo $(CFLAGS) > CFLAGS
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(XDP_PROG)

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

clsact:
	/usr/sbin/tc qdisc add dev eth0 clsact
	/usr/bin/touch clsact

load: $(XDP_PROG) clsact
	/usr/sbin/ip --force link set dev $(DEV) xdpgeneric obj $(XDP_PROG) sec xdp-rewrite-qname
	/usr/sbin/tc filter del dev eth0 egress || true
	echo 3 > /proc/sys/net/ipv4/ip_no_pmtu_disc
	/usr/sbin/ip -6 route flush cached
	/usr/bin/sleep 0.5
	/usr/sbin/tc filter add dev eth0 egress bpf da obj $(XDP_PROG) sec tc-restore-qname
	$(MAKE) show > show.out

unload:
	/usr/sbin/ip link set dev $(DEV) xdpgeneric off
	/usr/sbin/tc filter del dev eth0 egress
	/usr/sbin/tc qdisc del dev eth0 clsact
	/usr/bin/rm -f clsact

show:
	# see if loaded, xdpgeneric incoming and tc filter outgoing
	/usr/sbin/ip link show dev $(DEV)
	/usr/sbin/tc filter show dev eth0 egress

