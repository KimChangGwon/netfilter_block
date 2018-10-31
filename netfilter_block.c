#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size);
int isOK(unsigned char * data, uint8_t * Param);
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, uint8_t * flag, uint8_t * Param)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d \n", ret);
		*flag = isOK(data, Param);
		if(*flag) dump(data, ret);
	}
	fputc('\n', stdout);

	return id;
}
	
int isOK(unsigned char * data, uint8_t * Param){
#define IP_PROTOCOLFILED_OFFSET 9
#define TCP_HLENFILED_OFFSET 12
#define HOSTOFFSET 16
#define HOSTNAME 6
    uint32_t ipHLen = (data[0] & 0xF) << 2;
    uint8_t ipProtocol = data[IP_PROTOCOLFILED_OFFSET];
    uint32_t tcpDataOffset = ipHLen + (((data[ipHLen + TCP_HLENFILED_OFFSET] & 0xF0) >> 4) << 2);
    int of = 0;


    if(tcpDataOffset > ipHLen && (!memcmp(data + tcpDataOffset, "GET", 3) || !memcmp(data + tcpDataOffset, "POST", 4))){
	uint8_t * hostChkBuf = data + tcpDataOffset + HOSTOFFSET;	
	uint8_t * host = hostChkBuf + HOSTNAME;
	uint32_t i = 0;
	if(!memcmp(hostChkBuf, "Host", 4)) {
		uint8_t * cmpName = (uint8_t *)malloc(sizeof(uint8_t) * 1000);
		while(*(host + i) != '\x0d') {
			cmpName[i] = *(host + i);
			i++;
		}
		cmpName[i] = '\0';

		if(!memcmp(cmpName, Param, strlen(Param))) {
			puts("<<<<<<<<<<<<<<<<<<<<parameter host detected>>>>>>>>>>>>>>>>>>>>");
			return 0;
		}
		free(cmpName);
	}

	puts("");
    }
    return 1;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint8_t flag = 0;	
	u_int32_t id = print_pkt(nfa, &flag, (uint8_t *)data);
	printf("entering callback\n");
	if(!flag) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, argv[1]);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < 80; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

