//
// Created by Rodrigo Salazar on 10/1/23.
//

#include <string>

#ifndef TRACEROUTE_SOCKETCONTAINER_H
#define TRACEROUTE_SOCKETCONTAINER_H

namespace rodrigos::traceroute {

    struct RawSocketContainer {
        int m_fd = 0;

        ~RawSocketContainer();

        std::optional<int> open(const std::string &destAddr, int maxHops);

        bool send(const std::string &ipAddr);

        std::unique_ptr<char[], std::function<void(char *)>> receive(int &bytesReceived);
    };

    enum class AddressType {
        IPv4,
        IPv6
    };

    union IPAddress {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    };

    struct IPAddressWrapper {
        AddressType type;
        IPAddress address;

        bool operator==(const IPAddressWrapper &other) const {
          if (type != other.type) return false;
          if (type == AddressType::IPv4) {
            return address.ipv4.sin_addr.s_addr == other.address.ipv4.sin_addr.s_addr;
          } else {
            return memcmp(&address.ipv6.sin6_addr, &other.address.ipv6.sin6_addr, sizeof(in6_addr)) == 0;
          }
        }
    };
}

namespace std {
    template<>
    struct hash<rodrigos::traceroute::IPAddressWrapper> {
        std::size_t operator()(const rodrigos::traceroute::IPAddressWrapper& ip) const {
          if (ip.type == rodrigos::traceroute::AddressType::IPv4) {
            return std::hash<uint32_t>()(ip.address.ipv4.sin_addr.s_addr);
          } else {
            // Hashing IPv6 address: for simplicity, we're hashing based on the first and last 64 bits
            const uint64_t* parts = reinterpret_cast<const uint64_t*>(&ip.address.ipv6.sin6_addr);
            return std::hash<uint64_t>()(parts[0]) ^ std::hash<uint64_t>()(parts[1]);
          }
        }
    };
}

#endif //TRACEROUTE_SOCKETCONTAINER_H
