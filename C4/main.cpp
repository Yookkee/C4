#include "Unapplied.hpp"
#include "C4_wpcap.hpp"
#include "converter.hpp"
#include "C4_packet_creator.hpp"

extern std::vector <Adapter> Interfaces;
std::map<std::string, std::string> mac_ip;

unsigned int current = 0;

void arp_generator()
{
	Sleep(1000);
	C4_wpcap C4W(getInt(current)->AdapterName);
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);

	BYTE * ipv4 = new BYTE[4];
	conv_ip4_str_to_bytes(getInt(current)->IPaddress, ipv4); // swap inside
	std::cout << "Sending ARP..." << std::endl;
	C4W.ARP_Sender(
		getInt(current)->MAC,
		ipv4,
		fix_netmask(C4W.Get_Network_Mask())
		);
	delete[] ipv4;
}

/* mac_dest convert to BYTE(uchar) is not set */
void port_scanner()
{
	Sleep(1000);
	C4_wpcap C4W(getInt(current)->AdapterName); // set interfce
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL); // open interface

	BYTE * ipv4src = new BYTE[4]; // get memory to ip4 src address
	BYTE * ipv4dest = new BYTE[4]; // get memory to ip4 dest address
	BYTE * macdest = new BYTE[6]; // get memory to mac dest addr

	conv_ip4_str_to_bytes(getInt(current)->IPaddress, ipv4src); // convert and swap ip4src
	conv_ip4_str_to_bytes(mac_ip.begin()->second.c_str(), ipv4dest); // convert and swap ip4dest
	conv_mac_str_to_bytes(mac_ip.begin()->first.c_str(), macdest);

	C4W.TCP_Port_Scanner(
		macdest,
		getInt(current)->MAC,
		ipv4dest,
		ipv4src
		); // call TCP_port_scanner with clean args

	delete[] ipv4src;
	delete[] ipv4dest;
	delete[] macdest;
}

void main(int argc, char* argv[])
{
	std::cout << sizeof(TCP_PACKET) << std::endl;
	std::cout << "Interfaces list:" << std::endl;

	getInterfacesList();

	do
	{
		std::cout << "Choose Interface:" << std::endl;
		std::cin >> current;
	} while (current > Interfaces.size());

	std::cout << "Current Interface: " << current << std::ends;

	std::cout << "MAC " << getMAC(current) << std::endl;

	std::cout << "Ok" << std::endl;
	

	//--------------
	// Test C4_wpcap
	//--------------

	
	C4_wpcap C4W(getInt(current)->AdapterName);
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);
	std::thread th(arp_generator);
	std::cout << "Init Listener..." << std::endl;
	C4W.Listen_ARP(mac_ip);
	th.join();

	port_scanner();

}