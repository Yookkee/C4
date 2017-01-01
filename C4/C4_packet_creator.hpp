#ifndef _C4_PACKET_CREATOR_HPP_
#define _C4_PACKET_CREATOR_HPP_

typedef unsigned char BYTE;

struct ARP_PACKET
{
	// Ethernet
	BYTE mac_dest[6];	// Destination MAC address
	BYTE mac_src[6];	// Source MAC address
	BYTE protocol[2];	// Protocol (ARP)

	// ARP
	BYTE hard_type[2];	// HARDWARE TYPE
	BYTE proto_type[2];	// Protocol type
	BYTE hard_size;		// Size of hardware identifier
	BYTE proto_size;	// Size of protocol identifier
	BYTE opcode[2];		// ARP opcode (1-request, 2-reply)

	BYTE sender_mac[6];	// SOURCE MAC
	BYTE sender_ip[4];	// SOURCE IP
	BYTE dest_mac[6];	// DEST MAC
	BYTE dest_ip[4];	// DEST IP

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

	TCP_PACKET(const BYTE * mac_dest, const BYTE * mac_src, const BYTE * ip_dest, const BYTE * ip_src, unsigned short start_port);
	short Next_Port();
	void CALC_CHECKSUM();
};

struct DHCP_PACKET
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

	// UDP
	BYTE src_port[2];
	BYTE dest_port[2];
	BYTE lenght[2];
	BYTE udp_sum[2];

	// Bootstrap
	BYTE msg_type;
	BYTE hard_type;
	BYTE hard_addr_len;
	BYTE hops;
	BYTE transaction_id[4];
	BYTE zeros_20[20];
	BYTE client_mac[6];
	BYTE zeros_202[202];
	BYTE magic[4];
	BYTE op_msg_type[3];
	BYTE op_client_id[9];
	BYTE op_req_ip[6];
	BYTE op_param_req_list[6];
	BYTE op_end;
	BYTE padding[7];

	DHCP_PACKET(BYTE * mac);
	DHCP_PACKET(BYTE * mac, BYTE * req_id, BYTE * serv_ip);
};

void calc_ip_header_checksum(BYTE * addr);

void calc_tcp_header_checksum(BYTE * addr);

unsigned short calc_checksum(BYTE * addr, int len, unsigned short init_val, bool straight = false);

#endif