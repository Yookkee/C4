#ifndef _CONVERTER_HPP_
#define _CONVERTER_HPP_

#include <string>

std::string conv_mac_bytes_to_str(const unsigned char * arr);
std::string conv_ip4_bytes_to_str(const unsigned char * arr);

int fix_netmask(unsigned int netmask);

#endif