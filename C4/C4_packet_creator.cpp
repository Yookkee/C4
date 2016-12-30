#include "C4_packet_creator.hpp"
#include <cstring>
#include "converter.hpp"

//-------------------
// ARP Implementation
//-------------------

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

//-------------------
// TCP Implementation
//-------------------

TCP_PACKET::TCP_PACKET(const BYTE * _mac_dest, const BYTE * _mac_src, const BYTE * _ip_dest, const BYTE * _ip_src, unsigned short start_port)
{
	memset(mac_dest, 0, sizeof(TCP_PACKET));

	memcpy(mac_dest, _mac_dest, 6);
	memcpy(mac_src, _mac_src, 6);
	type[0] = 0x08;

	ver_head = 0x45;
	total_length[1] = 0x34;
	identification[0] = 0x43;
	identification[1] = 0x43;
	flags_offset[0] = 0x40;
	ttl = 0x80;
	protocol = 0x06;
	head_sum[0] = 0x00;
	head_sum[1] = 0x00;
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

	CALC_CHECKSUM();
}

short TCP_PACKET::Next_Port()
{
	short port = *(short *)reverse_bytes(dest_port, 2);
	short tmp = ++port;
	reverse_bytes((BYTE *)&port, 2);
	memcpy(dest_port, (BYTE *)&port, 2);

	CALC_CHECKSUM();

	return tmp;
}

void TCP_PACKET::CALC_CHECKSUM()
{
	*(unsigned short *)head_sum = 0;
	*(unsigned short *)checksum = 0;

	*(unsigned short *)&head_sum = calc_checksum(&ver_head, 20, 0, true);

	unsigned short sum = 0x1c + 0x06 + 4;
	int len = tcp_head_len_and_flags[0] >> 2;
	*(unsigned short *)&checksum = calc_checksum(src_ip, len + 8, sum, false);
	
	// calc_ip_header_checksum(reinterpret_cast<BYTE *>(this) + 14);
	// calc_tcp_header_checksum(reinterpret_cast<BYTE *>(this) + 34);
}

//--------------------
// DHCP Implementation
//--------------------

DHCP_PACKET::DHCP_PACKET(BYTE * mac)
{
	memset(mac_dest, 0x00, sizeof(DHCP_PACKET));
	// Eth
	memset(mac_dest, 0xff, 6);
	memcpy(mac_src, mac, 6);
	memcpy(type, "\x08\x00", 2);

	// IP
	memcpy(&ver_head, "\x45\x00\x01\x2c\xa8\x36\x00\x00", 8);
	memcpy(&ttl, "\xfa\x11\x17\x8b\x00\x00\x00\x00\xff\xff\xff\xff", 12);
	ttl = 0x80;

	// UDP
	memcpy(src_port, "\x00\x44\x00\x43\x01\x18\x59\x1f", 8);

	// Bootstrap
	memcpy(&msg_type, "\x01\x01\x06\x00\x00\x00\x3d\x1d", 12);
	memcpy(client_mac, mac, 6);
	memcpy(magic, "\x63\x82\x53\x63", 4);
	memcpy(op_msg_type, "\x35\x01\x01\x3d", 4);
	memcpy(op_client_id, "\x3d\x07\x01", 3);
	memcpy(op_client_id + 3, mac, 6);
	memcpy(op_req_ip, "\x32\x04", 2);
	memcpy(op_param_req_list, "\x37\x04\x01\x03\x06\x2a\xff", 7);
	memset(transaction_id + 2, rand() % 256, 1);		// transaction id randomization
	memset(transaction_id + 3, rand() % 256, 1);		// transaction id randomization

	*(unsigned short *)head_sum = 0;
	*(unsigned short *)&head_sum = calc_checksum(&ver_head, 20, 0, true);
	//calc_ip_header_checksum(reinterpret_cast<BYTE *>(this) + 14);
}

DHCP_PACKET::DHCP_PACKET(BYTE * mac, BYTE * req_ip, BYTE * serv_ip)
{
	memset(mac_dest, 0x00, sizeof(DHCP_PACKET));
	// Eth
	memset(mac_dest, 0xff, 6);
	memcpy(mac_src, mac, 6);
	memcpy(type, "\x08\x00", 2);

	// IP
	memcpy(&ver_head, "\x45\x00\x01\x2c\xa8\x37\x00\x00", 8);
	memcpy(&ttl, "\xfa\x11\x17\x8b\x00\x00\x00\x00\xff\xff\xff\xff", 12);
	ttl = 0x80;

	// UDP
	memcpy(src_port, "\x00\x44\x00\x43\x01\x18\x59\x1f", 8);

	// Bootstrap
	memcpy(&msg_type, "\x01\x01\x06\x00\x00\x00\x3d\x1d", 12);
	memcpy(client_mac, mac, 6);
	memcpy(magic, "\x63\x82\x53\x63", 4);
	memset(transaction_id + 2, rand() % 256, 1);		// transaction id randomization
	memset(transaction_id + 3, rand() % 256, 1);		// transaction id randomization

	memcpy(op_msg_type, "\x35\x01\x03", 3);
	memcpy(op_client_id, "\x3d\x07\x01", 3);
	memcpy(op_client_id + 3, mac, 6);
	/*for (int i = 0; i < 3; i++)
	{
		memset(op_client_id + 6 + i, rand() % 256, 1);
	}*/
	memcpy(op_req_ip, "\x32\x04", 2);
	memcpy(op_req_ip + 2, serv_ip, 4);
	memcpy(op_req_ip + 6, "\x36\x04", 2);
	req_ip[3] = 4;
	memcpy(op_req_ip + 8, req_ip, 4);
	memcpy(op_req_ip + 12, "\x37\x04\x01\x03\x06\x2a\xff\x00", 8);

	*(unsigned short *)head_sum = 0;

	*(unsigned short *)head_sum = calc_checksum(&ver_head, 20, 0, true);
	//calc_ip_header_checksum(reinterpret_cast<BYTE *>(this) + 14);
}

//--------
// Helpers
//--------

void calc_ip_header_checksum(BYTE * addr)
{
	
	int len = 20;
	long sum = 0;  /* assume 32 bit long, 16 bit short */
	unsigned short *ip_header = (unsigned short *)addr;
	ip_header[5] = 0;

	while (len > 1){
		sum += *((unsigned short*)ip_header)++;
		if (sum & 0x80000000)   /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)       /* take care of left over byte */
		sum += (unsigned short)*(unsigned char *)ip_header;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	unsigned short tmp = sum;
	tmp = ~tmp;
	((unsigned short *)addr)[5] = tmp;
}

void calc_tcp_header_checksum(BYTE * addr)
{
	int res = 0;
	unsigned short word = 0;

	*(short *)(addr + 16) = 0;

	res += 0x1c;
	res += 6;

	for (int i = 0; i < 16; ++i)
	{
		*(BYTE *)&word = *(addr + i * 2 + 1);
		*((BYTE *)&word + 1) = *(addr + i * 2);

		res += word;
		if (res > 0xffff)
		{
			res -= 0xffff;
			res += 1;
		}
	}

	for (int i = 0; i < 4; ++i)
	{
		*(BYTE *)&word = *(addr - 8 + i * 2 + 1);
		*((BYTE *)&word + 1) = *(addr - 8 + i * 2);

		res += word;
		if (res > 0xffff)
		{
			res -= 0xffff;
			res += 1;
		}
	}

	word = res;
	word = ~word;
	*(addr + 16) = *((BYTE *)&word + 1);
	*(addr + 17) = *(BYTE *)&word;

	return;
}

unsigned short calc_checksum(BYTE * addr, int len, unsigned short init_val, bool straight)
{
	long sum = init_val;  /* assume 32 bit long, 16 bit short */
	unsigned short *ip_header = (unsigned short *)addr;

	while (len > 1){
		if (straight)
			sum += *((unsigned short*)ip_header)++;
		else
		{
			unsigned short tmp;
			*(BYTE *)&tmp = *((BYTE *)ip_header + 1);
			*((BYTE *)&tmp + 1) = *(BYTE *)ip_header;

			sum += tmp;
			ip_header++;
		}

		if (sum & 0x80000000)   /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)       /* take care of left over byte */
		sum += (unsigned short)*(unsigned char *)ip_header;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	unsigned short tmp = sum;
	tmp = ~tmp;

	return tmp;
}