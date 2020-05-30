#include <header.h>

char * Host;
int Hsize;
char text[100];

bool ip_table() {
    system("iptable -F");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    return true;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

void useage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

bool netfilter(unsigned char * buf, char * Host){

    struct ip* ip;
    ip = (struct ip*)buf;
    u_int8_t ip_hlen;
    u_int16_t ip_tlen;
    ip_hlen = ip->ip_hl;
    ip_tlen = ntohs(ip->ip_len);
    buf += ip_hlen*4;

    struct tcphdr* tcp;
    tcp = (struct tcphdr*)buf;
    u_char tcplen;
    tcplen = tcp->th_off;
    buf += tcplen*4;

<<<<<<< HEAD
    int i,j=0,count=0; //gilgil.net  gilgil.net.naver.com  // gilgil.net.naver.com  gilgil.net
    char result;
=======
    int i,j=0;
>>>>>>> 0b24855b9573c95b6222bd460cf99a62f239aa4b

    if (ntohs(tcp->th_dport) == 80) {  // 80 port(http) 443 port(https)
        for (i=0;i<ip_tlen-(ip_hlen+tcplen)*4;i++){
            if (i % 16 == 0)
                printf("\n");
            printf("%02x ",buf[i]);

            if (buf[i]==0x48 && buf[i+1]==0x6f && buf[i+2]==0x73 && buf[i+3]==0x74) {  // Host
                printf("\n## find HOST ##\n");
                while(1) {
                    if(buf[i+6]==0x0d && buf[i+7]==0x0a){
                        break;
                    }
                    ++count;
                    text[j]=buf[i+6];
                    printf("buf = %02x\n",buf[i+6]);
                    i++;
                    j++;
                }
            }
        }
    }
    if (count == Hsize && memcmp(&text,Host,Hsize) == 0) {
        printf("\n차단\n");
        result = true;
    }
    else {
        printf("\n정상적인 사이트\n");
        result = false;
    }
    return result;
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
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

    ret = nfq_get_payload(tb, &data);   //data = firts packet add
    if (ret >= 0) {
        printf("\n*********************************************\n");
        dump(data,ret);
        printf("\n\n");
        printf("payload_len=%d ", ret);
    }

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,   // callback DROP or ACCEPT
          struct nfq_data *nfa, char *Host)
{
    (void)nfmsg; // for unused error
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    int ret;
    int v = NF_ACCEPT;
    u_char *data;
    ret= nfq_get_payload(nfa,&data);

    if (ret >= 0) {
        if (netfilter(data,Host)==true) {
            printf("DROP the Host \n");
            v = NF_DROP;
        }
        else {
            printf("ACCEPT the Host\n");
        }
    }  
    printf("\n");
    return nfq_set_verdict(qh, id, v, 0, NULL);  //DROP or ACCEPT

}

int main(int argc, char *argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    //struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        useage();
        return 0;
    }

    Host = argv[1];
    Hsize = strlen(Host);

    if (ip_table()!=true) {
        printf("iptable setting success");
        return 0;
    }

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
    qh = nfq_create_queue(h,  0, &cb, Host);  // 마지막 인자를 포인터 형으로 cb에 넘겨줄 수 있음
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
