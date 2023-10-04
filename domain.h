//
// Created by Rodrigo Salazar on 10/3/23.
//

#ifndef TRACEROUTE_DOMAIN_H
#define TRACEROUTE_DOMAIN_H

#include <string>
#include "RawSocketContainer.h"

std::string reverseDNSLookup(const IPAddressWrapper &addrWrapper);
std::string resolveDomainToIP(const std::string &domain);

#endif //TRACEROUTE_DOMAIN_H
