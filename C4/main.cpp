#include "Unapplied.hpp"
#include "C4_wpcap.hpp"
#include "converter.hpp"

extern std::vector <Adapter> Interfaces;
std::map<std::string, std::string> mac_ip;

unsigned int current = 0;


void main(int argc, char* argv[])
{

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
	C4W.Listen_ARP(mac_ip);
}