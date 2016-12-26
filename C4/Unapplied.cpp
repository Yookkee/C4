// #define _CRT_SECURE_NO_WARNINGS
#include "Unapplied.hpp"


/* WARNING: TOO NUCH BIG TO MEMORY!!! */
std::map<std::string, std::string> macman;
std::vector <Adapter> Interfaces;

void MacMan()
{
	// vector mac - manufacturer
	//std::vector<std::pair<std::string,std::string>> macman;

	std::ifstream fin("mac-manufacturer.txt");

	std::string line;
	std::string mac;
	int str = 5628;
	while (str--)
	{
		std::getline(fin, line);
		mac = line.substr(0, 6);
		if (line.length() > 8)
			line = line.substr(7);
		else
			line = "Undefined";
		macman.insert(std::make_pair(mac, line));
		//macman.push_back(std::make_pair(mac,line));
	}
	fin.close();

}

std::string FindManbyMac(const std::string& mac)
{
	auto it = macman.find(mac.substr(0, 6));
	return it->second;
}

std::string getMAC(int number)
{
	std::string mac;
	char m[3];

	for (int i(0); i < 6; i++)
	{
		sprintf(m, "%0.2X", Interfaces[number].MAC[i]);
		mac += m[0];
		mac += m[1];

	}

	return mac;
}

void getInterfacesList()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	UINT i = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			std::cout << "[" << i++ << "] " << pAdapter->Description << std::endl;
			//AdInfo.push_back(pAdapter);

			Interfaces.push_back(
				Adapter(
				pAdapter->AdapterName,
				pAdapter->Description,
				pAdapter->Address,
				pAdapter->IpAddressList.IpAddress.String,
				pAdapter->IpAddressList.IpMask.String,
				pAdapter->GatewayList.IpAddress.String,
				pAdapter->DhcpServer.IpAddress.String
				)
				);
			pAdapter = pAdapter->Next;
		}
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);
}

std::string getIntName(int num)
{
	return Interfaces[num].AdapterName;
}

struct Adapter * getInt(int idx)
{
	return &Interfaces[idx];
}
