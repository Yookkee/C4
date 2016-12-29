#include "C4_packet_creator.hpp"
#include <cstring>
#include "converter.hpp"

ARP_PACKET::ARP_PACKET(const BYTE * _mac_src, const BYTE * _ip_src)
{
	memset(mac_dest, 0xff, 6);
	memcpy(mac_src, _mac_src, 6);
	protocol[0] = 8;
	protocol[1] = 6;

	hard_type[0] = 0x00;
	hard_type[1] = 0x01;
	proto_type[0] = 0x08;
	proto_type[1] = 0x00;
	hard_size = 6;
	proto_size = 4;
	opcode[0] = 0x00;
	opcode[1] = 0x01;

	memcpy(sender_mac, _mac_src, 6);
	memcpy(sender_ip, _ip_src, 4);
	memset(dest_mac, 0, 6);
	memset(dest_ip, 0, 4);
}

TCP_PACKET::TCP_PACKET(const BYTE * _mac_dest, const BYTE * _mac_src, const BYTE * _ip_dest, const BYTE * _ip_src, unsigned short start_port)
{
	memset(mac_dest, 0, sizeof(TCP_PACKET));

	memcpy(mac_dest, _mac_dest, 6);
	memcpy(mac_src, _mac_src, 6);
	type[0] = 0x08;

	ver_head = 0x45;
	total_length[1] = 0x34;
	identification[0] = 0x41;
	identification[1] = 0xea;
	flags_offset[0] = 0x40;
	ttl = 0x80;
	protocol = 0x06;
	head_sum[0] = 0x23;
	head_sum[1] = 0x8e;
	memcpy(src_ip, _ip_src, 4);
	memcpy(dest_ip, _ip_dest, 4);

	//BYTE * port = new BYTE[2];
	reverse_bytes((BYTE *)&start_port, 2);
	memcpy(dest_port, &start_port, 2);

	src_port[0] = 0xd2;
	src_port[1] = 0xa2;
	seq_number[0] = 0xbe;
	seq_number[1] = 0xeb;
	seq_number[2] = 0x5c;
	seq_number[3] = 0x57;
	tcp_head_len_and_flags[0] = 0x80;
	tcp_head_len_and_flags[1] = 0x02;
	window_size[0] = 0x20;
	checksum[0] = 0x90;
	checksum[1] = 0x8e;
	memcpy(options, "\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02", 12);
}

short TCP_PACKET::Next_Port()
{
	short port = *(short *)reverse_bytes(dest_port, 2);
	short tmp = ++port;
	reverse_bytes((BYTE *)&port, 2);
	memcpy(dest_port, (BYTE *)&port, 2);
	return tmp;
}
