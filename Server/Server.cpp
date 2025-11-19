#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint32_t HEADER_MAGIC = 0x504B5450u; // 'PKTP'

enum Variant : uint8_t { PLAIN = 0, ENCRYPTED = 1, CONTROL = 2 };

#pragma pack(push,1)
struct PacketHeader {
    uint32_t magic;
    uint32_t pairId;
    uint8_t  variant;
    uint8_t  reserved[3];
    uint32_t plainSize;
    uint32_t encryptedSize;
    uint32_t totalPairs; // valid only for CONTROL
};
#pragma pack(pop)

struct ReceiveMetrics {
    uint32_t pairId;
    uint8_t variant; // 0 plain 1 encrypted
    uint32_t plainSize;
    uint32_t encryptedSize;
    uint64_t recvTsUs; // microseconds since epoch
    uint32_t payloadBytes; // received payload excluding header
};

void write_server_csv(const std::string& path, const std::vector<ReceiveMetrics>& rows) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if (!out.is_open()) { std::cerr << "Failed to open server metrics file: " << path << "\n"; return; }
    out << "pair_id,variant,plain_size,encrypted_size,recv_ts_us,payload_bytes\n";
    for (auto const& r : rows) {
        out << r.pairId << ',' << (int)r.variant << ',' << r.plainSize << ',' << r.encryptedSize << ',' << r.recvTsUs << ',' << r.payloadBytes << '\n';
    }
    std::cout << "Server metrics saved: " << rows.size() << " entries to " << path << "\n";
}

int main() {
    int port = 8080;
    std::cout << "Listen UDP port (default 8080): ";
    if (!(std::cin >> port) || port <= 0) port = 8080;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(sock); return 1; }
    std::cout << "Server listening on port " << port << "\n";

    std::vector<ReceiveMetrics> metrics;
    int expectedPairs = -1;
    int receivedPlain = 0;
    int receivedEncrypted = 0;

    while (true) {
        char buf[8192];
        sockaddr_in src{}; socklen_t srclen = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &srclen);
        if (n < 0) { perror("recvfrom"); break; }
        if (n < (int)sizeof(PacketHeader)) { std::cout << "Discarded short packet size=" << n << "\n"; continue; }

        PacketHeader hdr; std::memcpy(&hdr, buf, sizeof(hdr));
        if (hdr.magic != HEADER_MAGIC) { std::cout << "Discarded packet with bad magic." << std::endl; continue; }

        auto now = std::chrono::steady_clock::now();
        uint64_t tsUs = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();

        if (hdr.variant == CONTROL) {
            expectedPairs = (int)hdr.totalPairs;
            std::cout << "Control packet: expecting " << expectedPairs << " pairs." << std::endl;
            continue; // skip
        }
        if (expectedPairs < 0) { std::cout << "Data before control packet received; ignoring." << std::endl; continue; }

        ReceiveMetrics rm{};
        rm.pairId = hdr.pairId;
        rm.variant = hdr.variant;
        rm.plainSize = hdr.plainSize;
        rm.encryptedSize = hdr.encryptedSize;
        rm.recvTsUs = tsUs;
        rm.payloadBytes = (uint32_t)(n - sizeof(PacketHeader));
        metrics.push_back(rm);
        if (hdr.variant == PLAIN) ++receivedPlain; else if (hdr.variant == ENCRYPTED) ++receivedEncrypted;

        std::cout << "Received pairId=" << hdr.pairId << " variant=" << (int)hdr.variant << " payloadBytes=" << rm.payloadBytes << "\n";

        if (expectedPairs >= 0 && receivedPlain >= expectedPairs && receivedEncrypted >= expectedPairs) {
            std::cout << "All expected packets received." << std::endl;
            break;
        }
    }

    write_server_csv("data/server_metrics.csv", metrics);
    close(sock);
    return 0;
}}