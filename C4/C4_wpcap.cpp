#include "C4_wpcap.hpp"

C4_wpcap::C4_wpcap()
: alldevs(0), alldevs_count(0), curr_dev(0)
{}

C4_wpcap::~C4_wpcap()
{}

int C4_wpcap::Get_Int_List()
{
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return 1;
	}

	// Count interfaces
	pcap_if_t *d;
	for (d = alldevs, alldevs_count = 0; d; alldevs_count++, d = d->next);
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

int C4_wpcap::Set_Curr_Dev(char *)
{
	std::string qq;
	return 0;
}