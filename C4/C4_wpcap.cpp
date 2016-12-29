#include "C4_wpcap.hpp"
#include <iostream>
#include "converter.hpp"
#include "C4_packet_creator.hpp"
#include <vector>
#include "Unapplied.hpp"
#include <Winsock2.h>


C4_wpcap::C4_wpcap(const std::string & name)
: alldevs(0), alldevs_count(0), curr_dev(0), open_dev(0)
{
	Get_Int_List();
	Set_Curr_Dev(name);
}

C4_wpcap::~C4_wpcap()
{
	Free_Devices();
}

//-------------------------
// Constructor:
// -- Get Interface List
// -- Set Current Interface
//-------------------------
int C4_wpcap::Get_Int_List()
{
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return 1;
	}

	// Count interfaces
	pcap_if_t *d;
	for (d = alldevs, alldevs_count = 0; d; alldevs_count++, d = d->next);

	return 0;
}

int C4_wpcap::Print_Int_List()
{
	pcap_if_t *d;
	int i = 0;

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	return 0;
}

int C4_wpcap::Set_Curr_Dev(const std::string & name)
{
	pcap_if_t * d;
	unsigned int i;

	for (d = alldevs, i = 0;
		i < alldevs_count;
		d = d->next, i++)
	{
		std::string tmp = d->name;
		if (tmp.find(name) != std::string::npos)
		{
			curr_dev = d;
			return 0;
		}
	}
	
	return -1;
}

//--------------------------

int C4_wpcap::Listen_ARP(std::map<std::string, std::string> & mac_ip)
{
	if (!Is_Open())
	{
		std::cout << "Interface is not open" << std::endl;
		return 1;
	}
	//--------------------
	// Create Network mask
	//--------------------

	int netmask = Get_Network_Mask();

	//--------------------
	// Compile filter
	// Set filter
	//--------------------

	int status = Filter_Create("arp", netmask);
	if (status)
		return 1;

	//--------------------
	// Capturing
	//--------------------

	std::cout << "Capturing ARP replies" << std::endl;
	std::cout << "MAC - IP" << std::endl;

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	/* Retrieve the packets */
	clock_t t = clock();
	//Listen for 5 seconds
	while (clock() - t < 3000 && (res = pcap_next_ex(open_dev, &header, &pkt_data)) >= 0){

		if (res == 0)
			/* Timeout elapsed */
			continue;

		// check for response
		// 1 - request
		// 2 - reply
		if (*(pkt_data + 21) == 2)
		{
			// get mac and ip from packet data
			std::string mac = conv_mac_bytes_to_str((unsigned char *)(pkt_data + 22));
			std::string ip  = conv_ip4_bytes_to_str((unsigned char *)(pkt_data + 28));

			if (mac_ip.insert(std::make_pair(mac, ip)).second == true)
				std::cout << mac << " " << ip << std::endl;
		}
	}

	return 0;
}

int C4_wpcap::Listen_SYNACK()
{
	if (!Is_Open())
	{
		std::cout << "Interface is not open" << std::endl;
		return 1;
	}
	//--------------------
	// Create Network mask
	//--------------------

	int netmask = Get_Network_Mask();

	//--------------------
	// Compile filter
	// Set filter
	//--------------------

	int status = Filter_Create("tcp-syn", netmask);
	if (status)
		return 1;

	//--------------------
	// Capturing
	//--------------------

	std::cout << "SYN_ACK" << std::endl;

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	/* Retrieve the packets */
	clock_t t = clock();
	//Listen for 5 seconds
	while (clock() - t < 5000 && (res = pcap_next_ex(open_dev, &header, &pkt_data)) >= 0){

		if (res == 0)
			/* Timeout elapsed */
			continue;

		// src port 34 + 35
		short src_port;
		*((BYTE*)&src_port + 1) = *(pkt_data + 34);
		*((BYTE*)&src_port + 0) = *(pkt_data + 35);

		std::cout << "Open port: " << src_port << std::endl;
	}

	return 0;
}


void C4_wpcap::Free_Devices()
{
	pcap_freealldevs(alldevs);
}

int C4_wpcap::Get_Network_Mask()
{
	pcap_addr_t *a;
	DWORD netmask = 0;

	for (a = curr_dev->addresses; a && !netmask; a = a->next)
	{
		switch (a->addr->sa_family)
		{
		case AF_INET:
			netmask = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
			break;
		}
	}

	if (!netmask)
		netmask = 0xffffff;

	return netmask;
}

int C4_wpcap::Filter_Create(std::string filter, int netmask)
{
	//--------------------
	// Compile filter
	//--------------------

	struct bpf_program fcode;
	if (pcap_compile(open_dev, &fcode, "arp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 1;
	}

	//--------------------
	// Set filter
	//--------------------

	if (pcap_setfilter(open_dev, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 1;
	}

	return 0;
}

int C4_wpcap::Open_Device(const int pack_len, const int flag)
{
	/* Open the device */
	if ((open_dev = pcap_open(curr_dev->name,          // name of the device
		pack_len,            // portion of the packet to capture. 
		// 65536 guarantees that the whole packet will be captured on all the link layers
		flag,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", curr_dev->name);
		printf("\nUnable to open the adapter. %s\n", pcap_geterr(open_dev));
		return 1;
	}

	return 0;
}

bool C4_wpcap::Is_Open()
{
	return open_dev != 0;
}

int C4_wpcap::ARP_Sender(BYTE * mac, BYTE * ip, const unsigned int netmask)
{
	ARP_PACKET raw(mac, ip);
	BYTE * bytes = (BYTE *)&raw;

	int wildmask = 0xffffffff ^ netmask;

	BYTE arr[4] = { ip[3], ip[2], ip[1], ip[0] };
	unsigned int my_ip = *(int*)arr;

	unsigned int intface_addr = netmask & my_ip;
	intface_addr++;
	for (int i = 0; i < wildmask - 1; ++i)
	{
		arr[0] = *(((BYTE*)&intface_addr) + 3);
		arr[1] = *(((BYTE*)&intface_addr) + 2);
		arr[2] = *(((BYTE*)&intface_addr) + 1);
		arr[3] = *(((BYTE*)&intface_addr) + 0);

		memcpy(&bytes[38], arr, 4);

		if (pcap_sendpacket(open_dev, bytes, sizeof(ARP_PACKET) /* size */) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(open_dev));
			return 1;
		}

		intface_addr++;
	}



	return 0;
}

/* need 2 addition values for port-range  */
int C4_wpcap::TCP_Port_Scanner(const BYTE * mac_dest, const BYTE * mac_src, const BYTE * ip_dest, const BYTE * ip_src)
{
	TCP_PACKET raw(mac_dest, mac_src, ip_dest, ip_src, 7980); //create packet

	/*for (int i(0); i < sizeof(TCP_PACKET); i++)
	{
		printf("%x ", *((BYTE*)&raw + i));
		if ((i + 1) % 16 == 0)
			std::cout << std::endl;
		else if ((i + 1) % 8 == 0)
			std::cout << "\t";
	}*/

	std::cout << sizeof(TCP_PACKET) << std::endl;
	while (raw.Next_Port() < 8010)
	{
		if (pcap_sendpacket(open_dev, (BYTE*)&raw, sizeof(TCP_PACKET) /* size */) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(open_dev));
			return 1;
		}
	}

	return 0;
}

int C4_wpcap::DHCP_Sender(BYTE * mac)
{
	DHCP_PACKET raw(mac); //create packet
	std::cout << "sent " << sizeof(DHCP_PACKET) << " bytes." << std::endl;
	if (pcap_sendpacket(open_dev, (BYTE*)&raw, sizeof(DHCP_PACKET) /* size */) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(open_dev));
		return 1;
	}
	return 0;
}

int C4_wpcap::Listen_DHCP()
{
	if (!Is_Open())
	{
		std::cout << "Interface is not open" << std::endl;
		return 1;
	}
	//--------------------
	// Create Network mask
	//--------------------

	int netmask = Get_Network_Mask();

	//--------------------
	// Compile filter
	// Set filter
	//--------------------

	int status = Filter_Create("port 67", netmask);
	if (status)
		return 1;

	//--------------------
	// Capturing
	//--------------------

	std::cout << "Capturing DHCP(Listen_DHCP)" << std::endl;

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	/* Retrieve the packets */
	clock_t t = clock();
	//Listen for 5 seconds
	while (clock() - t < 3000 && (res = pcap_next_ex(open_dev, &header, &pkt_data)) >= 0){

		if (res == 0)
			/* Timeout elapsed */
			continue;

		// src port 34 + 35
		int serv_ip = *(int *)(pkt_data + 311);
		reverse_bytes((BYTE *)&serv_ip, 4);
		
		std::cout << "DHCP server: " << conv_ip4_bytes_to_str((BYTE *)&serv_ip) << std::endl;
	}

	return 0;
}
