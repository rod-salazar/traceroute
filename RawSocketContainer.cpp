//
// Created by Rodrigo Salazar on 10/1/23.
//

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip6.h>     // For struct ip6_hdr (IPv6)
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "RawSocketContainer.h"

RawSocketContainer::~RawSocketContainer() {
  close(m_fd);
}

std::optional<int> RawSocketContainer::open(const std::string &destAddr, int maxHops) {
  int sockfd;
  struct sockaddr_storage storage;
  memset(&storage, 0, sizeof(storage));

  // Determine if it's an IPv4 address
  if (inet_pton(AF_INET, destAddr.c_str(), &reinterpret_cast<struct sockaddr_in *>(&storage)->sin_addr)) {
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
      std::cerr << "Error creating IPv4 socket: " << strerror(errno) << std::endl;
      return std::nullopt;
    }

    if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, &maxHops, sizeof(maxHops)) < 0) {
      std::perror("Error setting TTL for IPv4");
      close(sockfd);
      return std::nullopt;
    }

    // Or, it might be an IPv6 address
  } else if (inet_pton(AF_INET6, destAddr.c_str(), &reinterpret_cast<struct sockaddr_in6 *>(&storage)->sin6_addr)) {
    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd < 0) {
      std::cerr << "Error creating IPv6 socket: " << strerror(errno) << std::endl;
      return std::nullopt;
    }

    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &maxHops, sizeof(maxHops)) < 0) {
      std::perror("Error setting hop limit for IPv6");
      close(sockfd);
      return std::nullopt;
    }
  } else {
    std::cerr << "Error: Invalid IP address format: " << destAddr << std::endl;
    return std::nullopt;
  }

  m_fd = sockfd;
  return m_fd;
}

bool RawSocketContainer::send(const std::string &ipAddr) {
  // Determine if IP is IPv4 or IPv6
  struct in_addr ipv4_addr;
  struct in6_addr ipv6_addr;

  if (inet_pton(AF_INET, ipAddr.c_str(), &ipv4_addr) == 1) {
    // IPv4 destination address
    sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ipv4_addr;

    // Construct ICMPv4 Echo Request
    icmp icmp_hdr;
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_hun.ih_idseq.icd_id = htons(1); // Identifier (arbitrary value)
    icmp_hdr.icmp_hun.ih_idseq.icd_seq = htons(1); // Sequence number (arbitrary value)
    icmp_hdr.icmp_cksum = 0;

    // Calculate ICMP checksum
    size_t packet_size = sizeof(icmp_hdr);
    assert(packet_size % 2 == 0);
    unsigned short* send_buffer = reinterpret_cast<unsigned short*>(&icmp_hdr);
    unsigned long sum = 0;
    for(int i = 0; i < packet_size / 2; ++i)
      sum += send_buffer[i];
    while (sum >> 16)
      sum = (sum & 0xFFFF) + (sum >> 16);
    icmp_hdr.icmp_cksum = ~static_cast<uint16_t>(sum);

    // Send ICMPv4 Echo Request
    if (sendto(m_fd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) <= 0) {
      std::cerr << "Error sending ipv4 packet: " << strerror(errno) << std::endl;
      return false;
    }
  } else if (inet_pton(AF_INET6, ipAddr.c_str(), &ipv6_addr) == 1) {
    // IPv6 destination address
    sockaddr_in6 dest_addr6;
    dest_addr6.sin6_family = AF_INET6;
    dest_addr6.sin6_addr = ipv6_addr;

    // Construct ICMPv6 Echo Request
    icmp6_hdr icmp6_hdr;
    icmp6_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_hdr.icmp6_code = 0;
    icmp6_hdr.icmp6_id = htons(1);   // Identifier (arbitrary value)
    icmp6_hdr.icmp6_seq = htons(1);  // Sequence number (arbitrary value)
    icmp6_hdr.icmp6_cksum = 0; // The kernel will compute this for ICMPv6 if you bind the socket properly

    // Send ICMPv6 Echo Request
    if (sendto(m_fd, &icmp6_hdr, sizeof(icmp6_hdr), 0, (struct sockaddr*)&dest_addr6, sizeof(dest_addr6)) <= 0) {
      std::cerr << "Error sending ipv6 packet: " << strerror(errno) << std::endl;
      return false;
    }
  } else {
    std::cerr << "Invalid IP address format: " << ipAddr << std::endl;
    return false;
  }

  return true;
}

std::unique_ptr<char[], std::function<void(char*)>> RawSocketContainer::receive(int &bytesReceived) {
  // Buffer to store incoming packets, assumption is that 1024 is enough for ICMP.
  size_t buffer_size = 1024;
  auto recv_buffer = std::make_unique<char[]>(buffer_size);

  struct sockaddr_storage sender_addr; // Use sockaddr_storage to be able to handle both IPv4 and IPv6
  socklen_t addrlen = sizeof(sender_addr);

  bytesReceived = recvfrom(m_fd, recv_buffer.get(), buffer_size, 0, (struct sockaddr*)&sender_addr, &addrlen);

  if (bytesReceived < 0) {
    perror("recvfrom");
    return nullptr;
  }

  if(bytesReceived < sizeof(struct ip) && bytesReceived < sizeof(struct ip6_hdr)) {
    // The packet is too small to be a valid IP packet.
    std::cerr << "Bytes received is too small for IP: " << bytesReceived << std::endl;
    return nullptr;
  }

  auto deleter = [](char* ptr) {
      delete[] ptr;
  };

  return std::unique_ptr<char[], decltype(deleter)>(recv_buffer.release(), deleter);
}