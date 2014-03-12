#include <Packet.h>
#include <stdio.h>

using namespace std;
namespace SimplePcapNs {


    Packet::Packet(
        int capturedLen,
        int realLen,
        int secOffset,
        int uSecOffset,
        u_char *packet
    ) {
        this->capturedLen = capturedLen;
        this->realLen = realLen;
        this->secondsOffset = secOffset;
        this->uSecondsOffset = uSecOffset;

		/* declare pointers to packet headers */
        const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
        const char *payload;                    /* Packet payload */

		int size_ip;
        int size_tcp;
        int size_payload;

        /* define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);

        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }

        this->src_ip = inet_ntoa(ip->ip_src);
        this->dst_ip = inet_ntoa(ip->ip_dst);

        /* determine protocol */
		switch(ip->ip_p) {
                case IPPROTO_TCP:                        
                        break;
                case IPPROTO_UDP:
                        printf("   Protocol: UDP\n");
                        return;
                case IPPROTO_ICMP:
                        printf("   Protocol: ICMP\n");
                        return;
                case IPPROTO_IP:
                        printf("   Protocol: IP\n");
                        return;
                default:
                        printf("   Protocol: unknown\n");
                        return;
        }

        /*
         *  OK, this packet is TCP.
         */

        /* define/compute tcp header offset */
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }

        this->src_port = ntohs(tcp->th_sport);
        this->dst_port = ntohs(tcp->th_dport);

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        /* define/compute tcp payload (segment) offset */
        this->data = string((const char *)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
    }

    int
    Packet::getCapturedLen()
    {
        return capturedLen;
    }

	int
	Packet::getSrcPort()
	{
		return this->src_port;
	}

	int
	Packet::getDstPort()
	{
		return this->dst_port;
	}

	char *
	Packet::getDstIP()
	{
		return this->dst_ip;
	}

	char *
	Packet::getSrcIP()
	{
		return this->src_ip;
	}
	
    int
    Packet::getRealLen()
    {
        return this->realLen;
    }

    int
    Packet::getSecondsOffset()
    {
        return secondsOffset;
    }

    int
    Packet::getMicroSecondsOffset()
    {
        return uSecondsOffset;
    }

    string
    Packet::getData()
    {
        return this->data;
    }

    string
    Packet::__toString()
    {
        char buff[256];
        snprintf(
            buff, sizeof(buff),
            "[ Packet: capLen: %d secOffset: %d uSecOffset: %d ]",
            capturedLen, secondsOffset, uSecondsOffset
        );
        return string(buff);
    }
}