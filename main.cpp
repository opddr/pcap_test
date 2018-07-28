#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  struct ip *ip_head;
  struct ether_header *eth;
  struct tcphdr *tcp;
  int ipsize;
  char *addr;
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
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    eth = (struct ether_header *)packet;
    packet+=sizeof(struct ether_header);
    printf("============================================\n");
    printf("src mac - %x:%x:%x:%x:%x:%x\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);

    printf("dst mac - %x:%x:%x:%x:%x:%x\n",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
	
    printf("ether_type = 0x%X\n",eth->ether_type);
    if( eth->ether_type != 0x08 )
    {
	printf("============================================\n");
	continue;
    }
	

    ip_head = (struct ip *)packet;
    packet += ip_head->ip_hl * 4;

    
    addr = inet_ntoa(ip_head->ip_src);   
    printf("src ip : %s\n",addr);
    addr = inet_ntoa(ip_head->ip_dst);   
    printf("dst ip : %s\n",addr);


    printf("ip_protocol = 0x%X \n",ip_head->ip_p);
    if( ip_head->ip_p != 6 )    
    {
	printf("============================================\n");
	continue;
    }


    tcp = (struct tcphdr *)packet;
    packet += tcp->th_off * 4;

    ipsize = (int)(ip_head->ip_len) - (ip_head->ip_hl * 4 + tcp->th_off * 4) ;
    printf("srcport : %hu\ndstport : %hu\n\n",htons(tcp->th_sport),htons(tcp->th_dport));
    for(int i = 0;i< ipsize; i++ )
	    putchar(packet[i]);

    printf("============================================\n");

 }

  pcap_close(handle);
  return 0;
}
