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
	conv_ip4_str_to_bytes(getInt(current)->IPaddress, ipv4);
	std::cout << "Sending ARP..." << std::endl;
	C4W.ARP_Sender(
		getInt(current)->MAC,
		ipv4,
		fix_netmask(C4W.Get_Network_Mask())
		);
	delete[] ipv4;
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



}