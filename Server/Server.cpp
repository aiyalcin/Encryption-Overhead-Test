#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>

#ifdef __linux__
// Linux networking headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#else
// Windows stub: real server runs only under Linux per user instruction.
int main(){ std::cout << "Server Linux implementation only. Run under Linux." << std::endl; return 0; }
#endif

#ifdef __linux__
// -----------------------------------------------------------------------------
// Protocol definitions
// -----------------------------------------------------------------------------
static const uint32_t HEADER_MAGIC = 0x504B5450u; // 'PKTP'
// Extend variants to include HASHED (4) and ENC_HASHED (5)
enum Variant : uint8_t { PLAIN=0, ENCRYPTED=1, CONTROL=2, ACK=3, HASHED=4, ENC_HASHED=5 };

#pragma pack(push,1)
struct PacketHeader {
    uint32_t magic;
    uint32_t pairId;
    uint8_t  variant;
    uint8_t  reserved[3];
    uint32_t plainSize;
    uint32_t encryptedSize;
    uint32_t totalPairs;
    uint32_t totalTests;
    uint32_t testIndex;
};
#pragma pack(pop)

// Simplified receive metrics (only what analysis now needs)
struct ReceiveMetrics {
    uint32_t pairId;
    uint8_t  variant;
    uint64_t recvTsUs; // system_clock microseconds
};

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------
static uint64_t nowMicro(){
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

static void write_server_csv(const std::string& path, const std::vector<ReceiveMetrics>& rows){
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if(!out.is_open()){
        std::cerr << "Failed to open server metrics file: " << path << "\n";
        return;
    }
    out << "pair_id,variant,recv_ts_us\n";
    for(const auto& r : rows){
        out << r.pairId << ',' << (int)r.variant << ',' << r.recvTsUs << '\n';
    }
}

// -----------------------------------------------------------------------------
// Main server loop
// -----------------------------------------------------------------------------
int main(){
    int port = 8080;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){ perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); close(sock); return 1; }
    std::cout << "Server listening on port " << port << "\n";

    int currentTest = 0;
    int totalTests  = 0;
    int expectedPairs = 0;
    int receivedPlain = 0;
    int receivedOther = 0;
    uint64_t testStartUs = 0;
    const int testTimeoutSec = 10;

    std::vector<ReceiveMetrics> metrics; // per-test

    while(true){
        char buf[16384];
        sockaddr_in src{}; socklen_t srclen = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &srclen);
        if(n < 0){ perror("recvfrom"); break; }
        if(n < (int)sizeof(PacketHeader)) continue;

        PacketHeader hdr{}; std::memcpy(&hdr, buf, sizeof(hdr));
        if(hdr.magic != HEADER_MAGIC) continue;
        uint64_t recvUs = nowMicro();

        if(hdr.variant == CONTROL){
            bool newTest = (hdr.testIndex != (uint32_t)currentTest);
            if(newTest){
                if(currentTest > 0 && !metrics.empty()){
                    std::string fn = "data/server_metrics_t" + std::to_string(currentTest) + ".csv";
                    write_server_csv(fn, metrics);
                    metrics.clear();
                }
                currentTest   = (int)hdr.testIndex;
                totalTests    = (int)hdr.totalTests;
                expectedPairs = (int)hdr.totalPairs;
                receivedPlain = 0;
                receivedOther = 0;
                testStartUs   = recvUs;
                std::cout << "Start test " << currentTest << "/" << totalTests
                          << " expecting " << expectedPairs << " pairs" << std::endl;
            } else {
                std::cout << "Duplicate control for test " << currentTest << std::endl;
            }
            PacketHeader ack{};
            ack.magic=HEADER_MAGIC; ack.pairId=0xFFFFFFFFu; ack.variant=ACK; ack.plainSize=hdr.plainSize; ack.encryptedSize=0; ack.totalPairs=hdr.totalPairs; ack.totalTests=hdr.totalTests; ack.testIndex=hdr.testIndex;
            char ackBuf[sizeof(PacketHeader)]; std::memcpy(ackBuf, &ack, sizeof(ack));
            if(sendto(sock, ackBuf, (int)sizeof(ackBuf), 0, (sockaddr*)&src, srclen) >= 0) std::cout << "ACK sent" << std::endl;
            continue;
        }

        if(currentTest == 0) continue; // ignore until control

        if(expectedPairs > 0 && (receivedPlain < expectedPairs || receivedOther < expectedPairs)){
            uint64_t elapsedSec = (recvUs - testStartUs)/1000000ull;
            if(elapsedSec > (uint64_t)testTimeoutSec){
                std::cout << "Test " << currentTest << " timeout" << std::endl;
                if(!metrics.empty()){
                    std::string fn = "data/server_metrics_t" + std::to_string(currentTest) + ".csv";
                    write_server_csv(fn, metrics);
                    metrics.clear();
                }
                expectedPairs=0;
                if(currentTest == totalTests) break;
                continue;
            }
        }

        if(hdr.testIndex != (uint32_t)currentTest) continue; // ignore future test data

        metrics.push_back({ hdr.pairId, hdr.variant, recvUs });
        if(hdr.variant == PLAIN) ++receivedPlain; else if(hdr.variant == ENCRYPTED || hdr.variant == HASHED || hdr.variant == ENC_HASHED) ++receivedOther;

        std::cout << "Test " << currentTest << " recv pairId=" << hdr.pairId << " variant=" << (int)hdr.variant
                  << " (" << receivedPlain << "/" << expectedPairs << " plain, "
                  << receivedOther << "/" << expectedPairs << " transformed)" << std::endl;

        if(expectedPairs > 0 && receivedPlain >= expectedPairs && receivedOther >= expectedPairs){
            std::cout << "Test " << currentTest << " complete" << std::endl;
            if(!metrics.empty()){
                std::string fn = "data/server_metrics_t" + std::to_string(currentTest) + ".csv";
                write_server_csv(fn, metrics);
                metrics.clear();
            }
            expectedPairs=0;
            if(currentTest == totalTests){ std::cout << "All tests done" << std::endl; break; }
        }
    }

    close(sock);
    return 0;
}
#endif // __linux__