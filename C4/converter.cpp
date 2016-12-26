#include "converter.hpp"

std::string conv_mac_bytes_to_str(const unsigned char * arr)
{
	std::string res = "";

	for (int i = 0; i < 6; ++i)
	{
		char tmp[3] = "\0";
		sprintf(tmp, "%0.2x", arr[i]);
		res += tmp;

		if (i != 5) 
			res += '-';
	}

	return res;
}

std::string conv_ip4_bytes_to_str(const unsigned char * arr)
{
	char result[16] = "\0"; // just in case
	std::string res = "";

	for (int i = 0; i < 4; i++)
	{
		sprintf(result, "%s%d", result, arr[i]);

		if (i != 3)
			sprintf(result, "%s.", result);
	}

	return result;
}

int fix_netmask(unsigned int netmask)
{
	unsigned int res = 0;
	for (int i = 0; i < sizeof(int) * 8; ++i)
	{
		res <<= 1;
		res += netmask & 1;
		netmask >>= 1;
	}

	return res;
}