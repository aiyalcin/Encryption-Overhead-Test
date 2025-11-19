#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <fstream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>


struct ReceivedPacket {
    int id;
    bool encrypted;          // true for encrypted phase packets
    size_t sizeBytes;         // payload size in bytes
    uint64_t recvTimestampUs; // microseconds since epoch (steady_clock)
};

// Save received metrics to CSV
void save_received_csv(const std::string& path, const std::vector<ReceivedPacket>& packets, int encryptedCount, int plainCount) {
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "Failed to open output file: " << path << "\n";
        return;
    }
    out << "id,encrypted,size_bytes,recv_timestamp_us\n";
    for (auto const& p : packets) {
        out << p.id << ',' << (p.encrypted?1:0) << ',' << p.sizeBytes << ',' << p.recvTimestampUs << '\n';
    }
    std::cout << "Saved " << packets.size() << " received packets (" << encryptedCount << " encrypted, " << plainCount << " plain) to " << path << "\n";
}

// Parse control packet of form: CONTROL <encCount> <plainCount>
bool parse_control(const char* data, size_t len, int& encCount, int& plainCount) {
    if (len < 7) return false;
    std::string s(data, len);
    if (s.rfind("CONTROL", 0) != 0) return false;
    std::istringstream iss(s.substr(7));
    if (!(iss >> encCount >> plainCount)) return false;
    return true;
}

void run_server(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0); // receive UDP datagrams
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Optional: set receive timeout (5s) to avoid indefinite blocking
    timeval tv{}; tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return;
    }

    std::cout << "Server listening on UDP port " << port << "...\n";

    int expectedEncrypted = 0;
    int expectedPlain = 0;
    bool controlReceived = false;

    // Receive control packet first
    while (!controlReceived) {
        char buf[4096];
        sockaddr_in src{}; socklen_t srclen = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &srclen);
        if (n < 0) {
            perror("recvfrom (control)");
            std::cout << "Retrying control packet...\n";
            continue; // keep trying
        }
        if (parse_control(buf, n, expectedEncrypted, expectedPlain)) {
            controlReceived = true;
            std::cout << "Control packet received. Expecting " << expectedEncrypted << " encrypted + " << expectedPlain << " plain packets.\n";
        } else {
            std::cout << "Ignored non-control packet before control received (size=" << n << ").\n";
        }
    }

    int totalExpected = expectedEncrypted + expectedPlain;
    std::vector<ReceivedPacket> received;
    received.reserve(totalExpected);

    for (int i = 0; i < totalExpected; ++i) {
        char buf[4096];
        sockaddr_in src{}; socklen_t srclen = sizeof(src);
        auto t0 = std::chrono::steady_clock::now(); // capture immediately before blocking call (optional)
        int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &srclen);
        if (n < 0) {
            perror("recvfrom");
            std::cerr << "Failed to receive packet " << i << "/" << totalExpected << ". Aborting.\n";
            break;
        }
        auto t1 = std::chrono::steady_clock::now();
        uint64_t tsUs = std::chrono::duration_cast<std::chrono::microseconds>(t1.time_since_epoch()).count();
        ReceivedPacket rp{};
        rp.id = i;
        rp.encrypted = (i < expectedEncrypted); // ordering matches client (encrypted phase first)
        rp.sizeBytes = static_cast<size_t>(n);
        rp.recvTimestampUs = tsUs;
        received.push_back(rp);
        std::cout << "Received packet " << (i+1) << "/" << totalExpected << " size=" << n << " enc=" << (rp.encrypted?"1":"0") << " recvUs=" << rp.recvTimestampUs << "\n";
    }

    save_received_csv("received_packets.csv", received, expectedEncrypted, expectedPlain);
    close(sock);
}

int main() {
    int port = 8080;
    std::cout << "Enter UDP port to listen on (default 8080): ";
    if (!(std::cin >> port) || port <= 0) { port = 8080; }
    run_server(port);
    return 0;
}

