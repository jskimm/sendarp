/*
ref : https://www.binarytides.com/raw-sockets-c-code-linux/ 
해당 소스를 skeleton으로 하여 작성하였습니다.
*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> 
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <netinet/if_ether.h>


int main() {

    /*

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       hw addr format (hrd)    |   protocol addr format (pro)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   hw length   |   prpto len   |        operation (op)         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    sender hw addr ( MAC )                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 sender protocol addr ( IP )                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    target hw addr ( MAC )                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 target protocol addr ( IP )                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    struct	ether_arp {
	struct	arphdr ea_hdr;	/* fixed-size header 
	u_char	arp_sha[6];	/* sender hardware address 
	u_char	arp_spa[4];	/* sender protocol address 
	u_char	arp_tha[6];	/* target hardware address 
	u_char	arp_tpa[4];	/* target protocol address 
    };  
    
    #define	arp_hrd	ea_hdr.ar_hrd
    #define	arp_pro	ea_hdr.ar_pro
    #define	arp_hln	ea_hdr.ar_hln
    #define	arp_pln	ea_hdr.ar_pln
    #define	arp_op	ea_hdr.ar_op
    
    */


    // IPPROTO_RAW; make raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // open socket fd
    printf("%d\n", sock);
    if(sock <= 0){
        puts("socket() error");
        exit(0);
    } 

    u_char smac[6] = {0x00, 0x0c, 0x29, 0x19, 0xfc, 0xd7};
    u_char dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /*
    raw socket for lower level (L2~3)
    defined <linux/if_packet.h>
    */
    struct sockaddr_ll addr;
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    // addr.sll_ifindex = 사용하고자하는 인터페이스의 인덱스;
    memcpy(addr.sll_addr, dmac, sizeof(dmac));

    struct ether_arp packet;


    packet.arp_hrd=htons(ARPHRD_ETHER);
    packet.arp_pro=htons(ETH_P_IP);
    packet.arp_hln=ETHER_ADDR_LEN;
    packet.arp_pln=sizeof(in_addr_t);
    packet.arp_op=htons(ARPOP_REQUEST);

    memcpy( packet.arp_sha, &smac, sizeof(packet.arp_sha) );
    memset( packet.arp_spa, htonl(inet_addr("192.168.248.128")), sizeof(packet.arp_spa) );
    memcpy( packet.arp_tha, &dmac, sizeof(packet.arp_sha) );
    memset( packet.arp_tpa, htonl(inet_addr("192.168.248.1")), sizeof(packet.arp_spa) );

    sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr *) &addr, sizeof(addr));

}
