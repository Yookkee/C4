#ifndef _C4_WPCAP_HPP_
#define _C4_WPCAP_HPP_

#include <string>
#include <map>
// include pcap.h last
#include "pcap.h"

class C4_wpcap
{
public:
	C4_wpcap(const std::string & name);
	~C4_wpcap();
	
	// Get broken network mask: 0xffffff for 255.255.255.0
	int Get_Network_Mask();
	// Check if current device is open
	bool Is_Open();
	// Open device with specific options
	pcap_t * Open_Device();
	// Create filter
	int Filter_Create(std::string filter, int netmask);
	// Run arp replies listener
	pcap_t * Listen_ARP(std::map<std::string, std::string> & mac_ip);

private:
	int Get_Int_List();
	int Print_Int_List();
	int Set_Curr_Dev(const std::string & name);
	void Free_Devices();

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	unsigned int alldevs_count;
	pcap_if_t *curr_dev;
	pcap_t * open_dev;
};

#endif