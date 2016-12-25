#ifndef _C4_WPCAP_HPP_
#define _C4_WPCAP_HPP_

#include <string>
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
private:
	pcap_if_t *alldevs;
	unsigned int alldevs_count;
	pcap_if_t *curr_dev;
};

#endif