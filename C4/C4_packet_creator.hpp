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
	BYTE dest_ip[4]; // 38-41

	ARP_PACKET(const BYTE * _mac_src, const BYTE * _ip_src);
};

struct TCP_PACKET
{
	// Ethernet
	BYTE mac_dest[6];
	BYTE mac_src[6];
	BYTE type[2];

	// IP
	BYTE ver_head;
	BYTE dif_serv_field;
	BYTE total_length[2];
	BYTE identification[2];
	BYTE flags_offset[2];
	BYTE ttl;
	BYTE protocol;
	BYTE head_sum[2];
	BYTE src_ip[4];
	BYTE dest_ip[4];

	// TCP
	BYTE src_port[2];
	BYTE dest_port[2];
	BYTE seq_number[4];
	BYTE ack[4];
	BYTE tcp_head_len_and_flags[2];
	BYTE window_size[2];
	BYTE checksum[2];
	BYTE urgent_pointer[2];
	BYTE options[12];

	TCP_PACKET(const BYTE * mac_dest, const BYTE * mac_src, const BYTE * ip_dest, const BYTE * ip_src);
};

#endif