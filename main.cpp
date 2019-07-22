#include <pcap.h>
#include <stdio.h>
#define eth_size 14

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct prt_ethernet{
    u_char eth_dmac[6];
    u_char eth_smac[6];
    u_short eth_type;

};

struct prt_ip{
    u_short i;
    u_short ip_tl;
    u_int32_t i1;
    u_char i3;
    u_int8_t ip_protocol;
    u_short i4;
    u_int8_t ip_sip[4];
    u_int8_t ip_dip[4];
};


struct prt_tcp{
    u_int8_t tcp_sport[2];
    u_int8_t tcp_dport[2];
    u_int32_t trash1;
    u_int32_t trash2;
    u_char tcp_off_trash;
    u_char trash;
    u_char t2;
    u_char t3;

};

int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    const struct prt_ethernet *ethernet; /* The ethernet header */
    const struct prt_ip *ip; /* The ethernet header */
    const struct prt_tcp *tcp;
    const u_char* tcp_data;
    int res = pcap_next_ex(handle, &header, &packet);
    int ip_size;
    int tcp_size;

    ethernet = (struct prt_ethernet*)(packet);
    ip = (struct prt_ip*)(packet+eth_size);
    ip_size = ip->ip_tl;
    tcp = (struct prt_tcp*)(packet+ip_size+eth_size);
    tcp_size = (tcp->tcp_off_trash)>>4;
    tcp_data = (packet+ip_size+eth_size+tcp_size);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if (ethernet->eth_type == 0x0800) {
            printf("EtherType : %x,The ip comes after ethernet.\n", ethernet->eth_type);
        }break;
    if (ip->ip_protocol == 6) {
            printf("ProtocolType : %d,The TCP comes after IP.\n", ip->ip_protocol);
         }break;



    printf("%u bytes captured\n", header->caplen);  
    printf("eth.dmac: %02x:%02x:%02x:%02x%02x:%02x\n",ethernet->eth_dmac[0], ethernet->eth_dmac[1], ethernet->eth_dmac[2], ethernet->eth_dmac[3],
            ethernet->eth_dmac[4], ethernet->eth_dmac[5]);
    printf("eth.smac: %02x:%02x:%02x:%02x%02x:%02x\n",ethernet->eth_smac[0],ethernet->eth_smac[1], ethernet->eth_smac[2], ethernet->eth_smac[3], ethernet->eth_smac[4], ethernet->eth_smac[5]);
    printf("ip.sip: %d. %d. %d. %d\n", ip->ip_sip[0],ip->ip_sip[1],ip->ip_sip[2],ip->ip_sip[3]);
    printf("ip.dip: %d. %d. %d. %d\n", ip->ip_dip[0],ip->ip_dip[1],ip->ip_dip[2],ip->ip_dip[3]);
    printf("tcp.sport: %d\n", (tcp->tcp_sport[0]>>8)|(tcp->tcp_sport[1]<<8));
    printf("tcp.dport: %d\n",  (tcp->tcp_dport[0]>>8)|(tcp->tcp_dport[1]<<8));
    printf("tcp.data: %c",tcp_data);



}
  pcap_close(handle);
  return 0;
}


