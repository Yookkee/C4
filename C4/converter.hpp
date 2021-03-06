#ifndef _CONVERTER_HPP_
#define _CONVERTER_HPP_

#include <string>

typedef unsigned char BYTE;

std::string conv_mac_bytes_to_str(const unsigned char * arr);
std::string conv_ip4_bytes_to_str(const unsigned char * arr);

void conv_ip4_str_to_bytes(const std::string & ipv4, BYTE * const arr);

int fix_netmask(unsigned int netmask);

#endif