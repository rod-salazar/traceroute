#include <iostream>
#include <cstring> // for memset
#include <cerrno> // for errno
#include <netinet/icmp6.h>
#include <netinet/ip.h> // for iphdr
#include <netinet/ip6.h>     // For struct ip6_hdr (IPv6)
#include <netinet/ip_icmp.h> // for icmphdr
#include <unistd.h> // for close()
#include <arpa/inet.h> // for inet_addr
#include <netdb.h> // for getnameinfo
#include <unordered_set>

#include "RawSocketContainer.h"

std::string reverseDNSLookup(const IPAddressWrapper &addrWrapper) {
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

std::string resolveDomainToIP(const std::string &domain) {
  struct addrinfo hints = {};
  struct addrinfo *result, *rp;

  hints.ai_family = AF_UNSPEC;  // Either IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;

  int ret = getaddrinfo(domain.c_str(), nullptr, &hints, &result);
  if (ret != 0) {
    std::cerr << "Error. getaddrinfo: " << gai_strerror(ret) << std::endl;
    return "";
  }

  // Return any result
  for (rp = result; rp != nullptr; rp = rp->ai_next) {
    char ipStr[INET6_ADDRSTRLEN];  // Big enough for both IPv4 and IPv6 addresses

    if (rp->ai_family == AF_INET) {
      struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
      inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, sizeof(ipStr));
      return ipStr;
    } else if (rp->ai_family == AF_INET6) {
      struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
      inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipStr, sizeof(ipStr));
      return ipStr;
    }
  }

  freeaddrinfo(result);
  return "";
}


/**
 * Requires root to create raw socket, so
 * sudo /Users/rod/code/traceroute/cmake-build-debug/traceroute
 */
int icmp_n_hops(std::string destIp, int hops, IPAddressWrapper &addrWrapper, bool& complete) {
  RawSocketContainer socket;

  auto fd = socket.open(destIp, hops);
  if (!fd.has_value()) {
    return -1;
  }

  bool send_result = socket.send(destIp);
  if (!send_result) {
    return -1;
  }

  int bytes_received;
  auto resp = socket.receive(bytes_received);
  if (!resp) {
    return -1;
  }


  struct ip* ip_hdr = reinterpret_cast<struct ip*>(resp.get());
  if (ip_hdr->ip_v == 4) {
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
      ssize_t ip_header_len = ip_hdr->ip_hl << 2; // IP header length in bytes.
      if (bytes_received >= ip_header_len + sizeof(struct icmp)) {
        icmp* icmp_hdr = reinterpret_cast<struct icmp*>(resp.get() + ip_header_len);
        addrWrapper.type = AddressType::IPv4;
        addrWrapper.address.ipv4.sin_addr = ip_hdr->ip_src;
        complete = icmp_hdr->icmp_type == ICMP_ECHOREPLY;
      } else {
        std::cerr << "Error: Expected response length of size > ip + icmp, instead received: " << bytes_received << std::endl;
        return -1;
      }
    } else {
      std::cerr << "Error: Expected IPPROTO_ICMP response header, instead received: " << std::to_string(ip_hdr->ip_p) << std::endl;
      return -1;
    }
  } else if (ip_hdr->ip_v == 6) {
    struct ip6_hdr* ip6_hdr = reinterpret_cast<struct ip6_hdr*>(resp.get());
    if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6) {
      // Assuming you've parsed the IPv6 header, get the ICMPv6 header
      struct icmp6_hdr* icmp6_hdr = reinterpret_cast<struct icmp6_hdr*>(resp.get() + sizeof(struct ip6_hdr));

      if (bytes_received >= sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
        addrWrapper.type = AddressType::IPv6;
        addrWrapper.address.ipv6.sin6_addr = ip6_hdr->ip6_src;
        complete = icmp6_hdr->icmp6_type == ICMP6_ECHO_REPLY;
      } else {
        std::cerr << "Error: Expected response length of size > ip6 + icmp6, instead received: " << bytes_received << std::endl;
        return -1;
      }
    } else {
      std::cerr << "Error: Expected IPPROTO_ICMPV6 response header, instead received: " << std::to_string(ip6_hdr->ip6_nxt) << std::endl;
      return -1;
    }
  } else {
    std::cerr << "Error: Unknown IP version: " << ip_hdr->ip_v << std::endl;
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <IP_ADDRESS>" << std::endl;
    return 1;
  }

  auto targetIP = resolveDomainToIP(argv[1]);

  int hop_n = 1;
  IPAddressWrapper ipAddr;
  bool complete = false;
  std::unordered_set<IPAddressWrapper> seen_addresses;

  while (!complete && icmp_n_hops(targetIP, hop_n++, ipAddr, complete) == 0) {
    std::string display = reverseDNSLookup(ipAddr);
    std::cout << display << std::endl;

    if (seen_addresses.contains(ipAddr)) {
      std::cout << "Cycle detected. Exiting." << std::endl;
      break;
    }
  }
}
