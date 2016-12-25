#ifndef _C4_WPCAP_HPP_
#define _C4_WPCAP_HPP_

#include <string>
#include <map>
// include pcap.h last
#include "pcap.h"

class C4_wpcap
{
public:
	C4_wpcap();
	~C4_wpcap();

	int Get_Int_List();
	int Print_Int_List();
	int Set_Curr_Dev(std::string name);

	pcap_t * Listen_arp(std::map<std::string, std::string> & mac_ip );
	void Free_Devices();
private:
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	unsigned int alldevs_count;
	pcap_if_t *curr_dev;
};

#endif