#include "Unapplied.hpp"
#include "C4_wpcap.hpp"
#include "converter.hpp"
#include <string>
#include "C4_packet_creator.hpp"
#include <limits>

extern std::vector <Adapter> Interfaces;
std::map<std::string, std::string> mac_ip;

std::string read_user_command();

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
void port_scanner(std::string & dest_mac, std::string & dest_ip)
{
	//-------------------------
	if (dest_ip == "192.168.1.3")
		dest_mac = "48-5a-b6-6d-de-09";
	//-------------------------

	Sleep(1000);
	C4_wpcap C4W(getInt(current)->AdapterName); // set interfce
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL); // open interface

	BYTE * ipv4src = new BYTE[4]; // get memory to ip4 src address
	BYTE * ipv4dest = new BYTE[4]; // get memory to ip4 dest address
	BYTE * macdest = new BYTE[6]; // get memory to mac dest addr

	conv_ip4_str_to_bytes(getInt(current)->IPaddress, ipv4src); // convert and swap ip4src
	conv_ip4_str_to_bytes(dest_ip, ipv4dest); // convert and swap ip4dest
	conv_mac_str_to_bytes(dest_mac, macdest);

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

void dhcp_generator()
{
	Sleep(1000);
	C4_wpcap C4W(getInt(current)->AdapterName);
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);

	// getInt(current)->MAC

	std::cout << "Sending DHCP..." << std::endl;
	C4W.DHCP_Sender( getInt(current)->MAC );
}

void nbns_generator(std::string & dest_mac, std::string & dest_ip)
{
	Sleep(1000);
	C4_wpcap C4W(getInt(current)->AdapterName);
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);

	BYTE * ipv4src = new BYTE[4]; // get memory to ip4 src address
	BYTE * ipv4dest = new BYTE[4]; // get memory to ip4 dest address
	BYTE * macdest = new BYTE[6]; // get memory to mac dest addr

	conv_ip4_str_to_bytes(getInt(current)->IPaddress, ipv4src); // convert and swap ip4src
	conv_ip4_str_to_bytes(dest_ip, ipv4dest); // convert and swap ip4dest
	conv_mac_str_to_bytes(dest_mac, macdest);

	std::cout << "Sending NBNS..." << std::endl;
	C4W.NBNS_Sender(getInt(current)->MAC, macdest, ipv4src, ipv4dest);

	delete[] ipv4src;
	delete[] ipv4dest;
	delete[] macdest;
}

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
	// ARP
	//--------------

	C4_wpcap C4W(getInt(current)->AdapterName);
	C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);
	std::thread th(arp_generator);
	std::cout << "Init Listener..." << std::endl;
	C4W.Listen_ARP(mac_ip);
	th.join();


	//--------------
	// DHCP
	//--------------

	std::thread th_dhcp(dhcp_generator);
	std::cout << "Init Listener for DHCP..." << std::endl;
	C4W.Listen_DHCP();
	th_dhcp.join();

	//--------------
	// USER COMMANDS
	//--------------

	std::string command;
	while (true)
	{
		command = read_user_command();


		//command = c_command;
		if (command.find("pscan ") == 0)
		{
			command = command.substr(6);

			for (std::map<std::string, std::string>::iterator it = mac_ip.begin();
				it != mac_ip.end();
				++it)
			{
				if (it->second == command || command == "192.168.1.3")
				{
					C4_wpcap C4W(getInt(current)->AdapterName);
					C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);

					std::thread th(port_scanner, it->first, /*it->second*/ command);

					std::cout << "Init Listener..." << std::endl;
					C4W.Listen_SYNACK();
					std::cout << "Listen to thread join ... ";
					th.join();
					std::cout << "joined." << std::endl;

					break;
				}
			}
		}
		else if (command.find("nbns ") == 0)
		{
			std::string ip = command.substr(5);

			for (auto it = mac_ip.begin(); it != mac_ip.end(); ++it)
			{
				if (it->second == ip)
				{
					C4_wpcap C4W(getInt(current)->AdapterName);
					C4W.Open_Device(C4_PACKET_MAX_LEN, PCAP_OPENFLAG_NOCAPTURE_LOCAL);

					std::thread th(nbns_generator, it->first, it->second);

					std::cout << "Init NBNS Listener..." << std::endl;
					C4W.NBNS_Listener();
					std::cout << "Listen to thread join ... ";
					th.join();
					std::cout << "joined." << std::endl;

					break;
				}
			}
		}
	}

	//port_scanner(); //pscan

}

std::string read_user_command()
{
	static bool ok = false;
	std::string command;

	// Welcome
	std::cout << ">>> ";

	// Clear buffer
	if (ok == false)
	{
		std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
		ok = true;
	}

	// Read command
	std::getline(std::cin, command, '\n');

	// Return command
	return command;
}