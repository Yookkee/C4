#include "C4_packet_creator.hpp"
#include <cstring>

ARP_PACKET::ARP_PACKET(const BYTE * _mac_src, const BYTE * _ip_src)
{
	memset(mac_dest, 0xff, 6);
	memcpy(mac_src, _mac_src, 6);
	*protocol = 0x0806;

	*hard_type = 0x0001;
	*proto_type = 0x8000;
	hard_size = 6;
	proto_size = 4;
	*opcode = 0x0001;

	memcpy(sender_mac, _mac_src, 6);
	memcpy(sender_ip, _ip_src, 4);
	memcpy(dest_mac, 0, 6);
	memcpy(dest_ip, 0, 4);
}