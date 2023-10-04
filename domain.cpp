//
// Created by Rodrigo Salazar on 10/3/23.
//

#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
#include "domain.h"

using namespace rodrigos::traceroute;

std::string rodrigos::traceroute::reverseDNSLookup(const IPAddressWrapper &addrWrapper) {
  char node[NI_MAXHOST + INET6_ADDRSTRLEN + 3]; // 3 for the ' ()', and INET6_ADDRSTRLEN to accommodate IPv6
  char ipStr[INET6_ADDRSTRLEN]; // Adjusted for IPv6

  if (addrWrapper.type == AddressType::IPv4) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr = addrWrapper.address.ipv4.sin_addr;

    inet_ntop(AF_INET, &(sa.sin_addr), ipStr, INET_ADDRSTRLEN);
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sockaddr_in), node, sizeof(node), nullptr, 0, NI_NAMEREQD)) {
      return ipStr;
    }
  } else if (addrWrapper.type == AddressType::IPv6) {
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(struct sockaddr_in6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_addr = addrWrapper.address.ipv6.sin6_addr;

    inet_ntop(AF_INET6, &(sa6.sin6_addr), ipStr, INET6_ADDRSTRLEN);
    if (getnameinfo((struct sockaddr*)&sa6, sizeof(sockaddr_in6), node, sizeof(node), nullptr, 0, NI_NAMEREQD)) {
      return ipStr;
    }
  } else {
    return "Invalid address type";
  }

  int node_len = 0;
  while (node[node_len]) {
    node_len++;
  }
  node[node_len++] = ' ';
  node[node_len++] = '(';
  int ipStr_len = 0;
  while (ipStr[ipStr_len]) {
    // can do memcpy instead
    node[node_len++] = ipStr[ipStr_len++];
  }
  node[node_len++] = ')';
  node[node_len] = 0;
  return node;
}

std::string rodrigos::traceroute::resolveDomainToIP(const std::string &domain) {
  struct addrinfo hints = {};
  struct addrinfo *result, *rp;

  hints.ai_family = AF_UNSPEC;  // Either IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;

  int ret = getaddrinfo(domain.c_str(), nullptr, &hints, &result);
  if (ret != 0) {
    std::cerr << "Error. getaddrinfo: " << gai_strerror(ret) << std::endl;
    return "";
  }

  // Prefer ipv4

  char ipStr4[15] = {0};
  char ipStr6[INET6_ADDRSTRLEN] = {0};
  for (rp = result; rp != nullptr; rp = rp->ai_next) {

    if (rp->ai_family == AF_INET) {
      struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
      inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr4, sizeof(ipStr4));
    } else if (rp->ai_family == AF_INET6) {
      struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
      inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipStr6, sizeof(ipStr6));
    }
  }

  freeaddrinfo(result);
  return ipStr4[0] == 0 ? ipStr6 : ipStr4;
}