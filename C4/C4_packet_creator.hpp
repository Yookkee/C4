#ifndef _C4_PACKET_CREATOR_HPP_
#define _C4_PACKET_CREATOR_HPP_

typedef unsigned char BYTE;

struct ARP_PACKET
{
	// Ethernet
	BYTE mac_dest[6];
	BYTE mac_src[6];
	BYTE protocol[2];

	// ARP
	BYTE hard_type[2];
	BYTE proto_type[2];
	BYTE hard_size;
	BYTE proto_size;
	BYTE opcode[2];

	BYTE sender_mac[6];
	BYTE sender_ip[4];
	BYTE dest_mac[6];
	BYTE dest_ip[4];

	ARP_PACKET(const BYTE * _mac_src, const BYTE * _ip_src);
};

#endif