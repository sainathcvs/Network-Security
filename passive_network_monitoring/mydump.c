/*
timestamp
source MAC address
destination MAC address
EtherType
packet length
source IP and port Done
destination IP address and port Done
protocol type (e.g., "TCP", "UDP", "ICMP", "OTHER") Done
raw content of the packet payload (hint 4)
*/
#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."
/* Ethernet protocol ID's */
#define	ETHERTYPE_IP		0x0800//IP
#define	ETHERTYPE_ARP		0x0806//ARP

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ether.h>



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
	uint16_t        sport;	/* source port */
	uint16_t        dport;	/* destination port */
	uint16_t        udp_length;
	uint16_t        udp_sum;	/* checksum */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

int StrStr(char *str, char *substr)
{
	int i=1;
	  while (*str) 
	  {
		    char *Begin = str;
		    char *pattern = substr;
		    
		    // If first character of sub string match, check for whole string
		    while (*str && *pattern && *str == *pattern) 
			{
			      str++;
			      pattern++;
		    }
		    // If complete sub string match, return starting address 
		    if (!*pattern)
		    	  return i;
		    	  
		    str = Begin + 1;	// Increament main string 
	  }
	  return 0;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* convert the timestamp to readable format */
    struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	nowtime = header->ts.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);	

	static int count = 1;                   /* packet counter */
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	char *str_tmp = malloc(sizeof(char)*100);
	char *str_bkup = malloc(sizeof(char)*1000);
	int i;
	int size_ip;
	int size_tcp;
	int size_udp;
	int size_icmp;
	int size_payload;
	u_char *ether_dest;
	u_char *ether_src;
	u_char *protocol_name;
	char *type_ether;

	sprintf(str_tmp,"\n\n%s",buf);//timestamp--------------------------------
	str_bkup = strcat(str_bkup,str_tmp);
	count++;
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	//print host addresses
    sprintf(str_tmp," ");//" %s\n",  inet_ntop(ethernet->ether_dhost));
    str_bkup = strcat(str_bkup,str_tmp);
    i = ETHER_ADDR_LEN;
    ether_src = ethernet->ether_shost;
	do{
        sprintf(str_tmp,"%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ether_src++);//-------------------------------
        str_bkup = strcat(str_bkup,str_tmp);
    }while(--i>0);
	i = ETHER_ADDR_LEN;
	ether_dest = ethernet->ether_dhost;
	sprintf(str_tmp,"->");
	str_bkup = strcat(str_bkup,str_tmp);
	do{
        sprintf(str_tmp,"%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ether_dest++);//----------------------------------
        str_bkup = strcat(str_bkup,str_tmp);
    }while(--i>0);

	sprintf(str_tmp," type 0x%x",ntohs(ethernet->ether_type));//------------------------------------------------
	str_bkup = strcat(str_bkup,str_tmp);

	sprintf(str_tmp," len %d", header->len);//------------------------------------------
	str_bkup = strcat(str_bkup,str_tmp);
	/* define/compute ip header offset */
	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		/* print source and destination IP addresses */
		
		/* determine protocol */	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				protocol_name = "TCP";
				break;
			case IPPROTO_UDP:
				protocol_name = "UDP";
				return;
			case IPPROTO_ICMP:
				protocol_name = "ICMP";
				return;
			default:
				protocol_name = "unknown";
				return;
		}
		//printf("i moved %s\n",protocol_name);
	
		/*
		 *  OK, this packet is TCP.
		 */
		if(strcmp(protocol_name,"TCP")==0){
		/* define/compute tcp header offset */
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			//printf(" size of packet: %u\n",size_tcp);--------------------------------------size tcp
			sprintf(str_tmp," %s:%d", inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp,"->%s:%d", inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp," %s", protocol_name);
			str_bkup = strcat(str_bkup,str_tmp);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		}else if(strcmp(protocol_name,"UDP")==0){
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			size_udp = 8;
			//printf(" size of packet: %u\n",size_tcp);--------------------------------------size tcp
			sprintf(str_tmp," %s:%d", inet_ntoa(ip->ip_src),ntohs(udp->sport));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp,"->%s:%d", inet_ntoa(ip->ip_dst),ntohs(udp->dport));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp," %s", protocol_name);
			str_bkup = strcat(str_bkup,str_tmp);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
		}else if(strcmp(protocol_name,"ICMP")==0){
			size_icmp = 8;
			//printf(" size of packet: %u\n",size_tcp);--------------------------------------size tcp
			sprintf(str_tmp," %s", inet_ntoa(ip->ip_src));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp,"->%s", inet_ntoa(ip->ip_dst));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp," %s", protocol_name);
			str_bkup = strcat(str_bkup,str_tmp);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
		}else{
			sprintf(str_tmp," %s", inet_ntoa(ip->ip_src));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp,"->%s", inet_ntoa(ip->ip_dst));
			str_bkup = strcat(str_bkup,str_tmp);
			sprintf(str_tmp," %s", protocol_name);
			str_bkup = strcat(str_bkup,str_tmp);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip);
		}
	}else if((ntohs(ethernet->ether_type) == ETHERTYPE_ARP)||(ntohs(ethernet->ether_type) == ETHERTYPE_REVARP)){
		//do nothing
		if(ntohs(ethernet->ether_type) == ETHERTYPE_REVARP){
			sprintf(str_tmp," Rev ARP");
			str_bkup = strcat(str_bkup,str_tmp);
		}else{
			sprintf(str_tmp," ARP");
			str_bkup = strcat(str_bkup,str_tmp);
		}
	}else{
		//do nothing
	}
	
	/* define/compute tcp payload (segment) offset */
	if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP){
		payload = (u_char *)(packet + SIZE_ETHERNET);	
		/* compute tcp payload (segment) size */
		size_payload = (header->len) - SIZE_ETHERNET;
	}
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		if(args!=NULL && StrStr(payload, (char *)args)!=0){
			printf("%s",str_bkup);
			printf("\n");
			print_payload(payload, size_payload);
		}else if(args!=NULL){
			printf("%s",str_bkup);
			printf("\n");
			print_payload(payload, size_payload);
		}
	}else if(args==NULL && size_payload == 0){
			printf("%s",str_bkup);
	}

	return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char *expression_given;
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */
	bool is_inteface_specified = false;
	bool is_read_from_file = false;
	bool is_search_with_string = false;
	bool is_filter_given = false;

	char option;
	char *filename;
	char *str;
	while ((option = getopt(argc, argv, "i:r:s:p")) != -1) {
		switch(option) {
			case 'i':
				dev = optarg;
				printf("interface: %s\n", dev);
				is_inteface_specified = true;
				break;
			case 'r':
				filename = optarg;
				is_read_from_file = true;
				printf("file: %s\n", filename);
				break;
			case 's':
				str = optarg;
				is_search_with_string = true;
				printf("String: %s\n", str);
				break;
			case '?': 
				printf("error: unrecognized command-line options \n");
				return 0;
			default:
				printf("Default case?!\n");
				return 0;
		}
	}

	if (optind == argc - 1){
		expression_given = argv[optind];
		is_filter_given = true;
	}
	else if (optind < argc -1) {
		printf("error: unrecognized command-line options\n");
		return 0;
	}
	if(dev != NULL){
		if(strcmp(dev,"any")==0){
			is_inteface_specified = false;
		}
	}
	if(!is_read_from_file){
		if(!is_inteface_specified){
			/* find a capture device if not specified on command-line */
			dev = pcap_lookupdev(errbuf);
			if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n",
				    errbuf);
				exit(EXIT_FAILURE);
			}
		}
		
		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			    dev, errbuf);
			net = 0;
			mask = 0;
		}

		/* print capture info */
		printf("Device: %s\n", dev);
		printf("Number of packets: %d\n", num_packets);
	 	printf("Filter expression: %s\n", expression_given);

		/* open capture device */
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}
	}else{
		pcap_t *pcap;
		struct pcap_pkthdr header;
		const unsigned char *packet;
		handle = pcap_open_offline(filename, errbuf);
		if (pcap == NULL)
		{
			fprintf(stderr, "error reading pcap file: %s\n", errbuf);
			exit(1);
		}
	}

	if(is_filter_given){
		/* compile the filter expression */
		if (pcap_compile(handle, &fp, expression_given, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
			    expression_given, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
			    expression_given, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}

	pcap_loop(handle, num_packets, got_packet, str);
	/* cleanup */
	if(is_filter_given){
		pcap_freecode(&fp);
	}
	if(handle != NULL){
		pcap_close(handle);
	}

	printf("\nCapture complete.\n");

return 0;
}

