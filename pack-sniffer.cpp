#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Function to extract domain name from DNS payload
std::string extract_dns_name(const u_char *payload, int payload_len) {
    std::string name;
    int pos = 0;

    while (pos < payload_len) {
        uint8_t len = payload[pos];
        if (len == 0) break; // End of domain name
        pos++;

        name.append(reinterpret_cast<const char*>(payload + pos), len);
        name.append(".");
        pos += len;
    }

    if (!name.empty() && name.back() == '.') {
        name.pop_back(); // Remove trailing dot
    }

    return name;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // Not an IP packet
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_header->ip_p != IPPROTO_UDP) {
        return; // Not a UDP packet
    }

    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2));
    if (ntohs(udp_header->uh_dport) != 53) {
        return; // Not a DNS request (DNS uses port 53)
    }

    // Calculate DNS payload position
    int ip_header_len = ip_header->ip_hl << 2;
    int udp_header_len = sizeof(struct udphdr);
    const u_char *dns_payload = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
    int dns_payload_len = pkthdr->len - (sizeof(struct ether_header) + ip_header_len + udp_header_len);

    // Parse DNS header
    struct dns_header *dns_hdr = (struct dns_header *)dns_payload;
    if (ntohs(dns_hdr->qdcount) < 1) {
        return; // No questions in the DNS packet
    }

    // Extract domain name from DNS question section
    const u_char *dns_question = dns_payload + sizeof(struct dns_header);
    std::string domain_name = extract_dns_name(dns_question, dns_payload_len - sizeof(struct dns_header));

    std::cout << "DNS Query: " << domain_name << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}
