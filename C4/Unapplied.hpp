#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <sstream>
#include <thread>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")


#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

struct Adapter
{
	std::string AdapterName;
	std::string AdapterDescription;
	unsigned char MAC[6];
	std::string IPaddress;
	std::string IPmask;
	std::string IPgateway;
	std::string IPdhcp;

	Adapter(std::string Name, std::string Desc, unsigned char* mac, std::string IP,
		std::string Mask, std::string Gateway, std::string DHCP)
		:
		AdapterName(Name),
		AdapterDescription(Desc),
		IPaddress(IP),
		IPmask(Mask),
		IPgateway(Gateway),
		IPdhcp(DHCP)
	{
		memcpy(MAC, mac, 6);
	};
};

std::string FindManbyMac(const std::string& mac);

void MacMan();

std::string getMAC(int number);

void getInterfacesList();

std::string getIntName(int num);

struct Adapter * getInt(int idx);