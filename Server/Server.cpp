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
#include <netinet/udp.h>
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
// Variant codes
// 0 plain data, 1 encrypted data, 2 control (start test), 3 ack (response to control)
enum Variant : uint8_t { PLAIN = 0, ENCRYPTED = 1, CONTROL = 2, ACK = 3 };

#pragma pack(push,1)
struct PacketHeader {
    uint32_t magic;        // HEADER_MAGIC
    uint32_t pairId;       // Pair index (0xFFFFFFFF for control/ack)
    uint8_t  variant;      // Variant code
    uint8_t  reserved[3];  // Padding
    uint32_t plainSize;    // Plaintext size (for control: configured size per pair)
    uint32_t encryptedSize;// Encrypted size (0 for plain/control/ack)
    uint32_t totalPairs;   // Pairs per test (CONTROL/ACK)
    uint32_t totalTests;   // Total tests (CONTROL/ACK)
    uint32_t testIndex;    // 1-based test index
};
#pragma pack(pop)

// Per-packet receive metrics
struct ReceiveMetrics {
    uint32_t pairId;
    uint8_t  variant;       // 0 plain, 1 encrypted
    uint32_t plainSize;
    uint32_t encryptedSize;
    uint64_t recvTsUs;      // Microseconds since steady_clock epoch
    uint32_t payloadBytes;  // Bytes excluding header
};

// -----------------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------------
static uint64_t nowMicro(){
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

static void write_server_csv(const std::string& path, const std::vector<ReceiveMetrics>& rows){
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if(!out.is_open()){
        std::cerr << "Failed to open server metrics file: " << path << "\n";
        return;
    }
    out << "pair_id,variant,plain_size,encrypted_size,recv_ts_us,payload_bytes\n";
    for(const auto& r : rows){
        out << r.pairId << ',' << (int)r.variant << ',' << r.plainSize << ','
            << r.encryptedSize << ',' << r.recvTsUs << ',' << r.payloadBytes << '\n';
    }
}

// -----------------------------------------------------------------------------
// Main server loop
// -----------------------------------------------------------------------------
int main(){
    // Configuration input
    int port = 8080;
    std::cout << "Listen UDP port (default 8080): ";
    if(!(std::cin >> port) || port <= 0) port = 8080;

    // UDP socket setup
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){ perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); close(sock); return 1; }
    std::cout << "Server listening on port " << port << "\n";

    // Test tracking state
    int currentTest       = 0;
    int totalTests        = 0;
    int expectedPairs     = 0;
    int receivedPlain     = 0;
    int receivedEncrypted = 0;
    uint64_t testStartUs  = 0;
    bool testActive       = false;
    bool testTimedOut     = false;
    const int testTimeoutSec = 10; // seconds

    std::vector<ReceiveMetrics> metrics; // metrics for current test

    // Receive loop
    while(true){
        // Receive datagram
        char buf[8192];
        sockaddr_in src{}; socklen_t srclen = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&src, &srclen);
        if(n < 0){ perror("recvfrom"); break; }
        if(n < (int)sizeof(PacketHeader)){
            std::cout << "Discarded short packet size=" << n << '\n';
            continue;
        }

        // Parse header
        PacketHeader hdr{}; std::memcpy(&hdr, buf, sizeof(hdr));
        if(hdr.magic != HEADER_MAGIC){
            std::cout << "Discarded packet with bad magic." << std::endl;
            continue;
        }
        uint64_t recvUs = nowMicro();

        // Handle CONTROL packets (start or duplicate of test)
        if(hdr.variant == CONTROL){
            bool newTest = (hdr.testIndex != (uint32_t)currentTest);
            if(newTest){
                // Flush previous test data
                if(currentTest > 0 && !metrics.empty()){
                    std::string fn = "data/server_metrics_t" + std::to_string(currentTest) + ".csv";
                    write_server_csv(fn, metrics);
                    metrics.clear();
                }
                currentTest        = (int)hdr.testIndex;
                totalTests         = (int)hdr.totalTests;
                expectedPairs      = (int)hdr.totalPairs;
                receivedPlain      = 0;
                receivedEncrypted  = 0;
                testStartUs        = recvUs;
                testActive         = true;
                testTimedOut       = false;
                std::cout << "Control: start test " << currentTest << "/" << totalTests
                          << " expecting " << expectedPairs << " pairs" << std::endl;
            } else {
                std::cout << "Duplicate control for test " << currentTest << "; re-ACK" << std::endl;
            }

            // Send ACK
            PacketHeader ack{};
            ack.magic         = HEADER_MAGIC;
            ack.pairId        = 0xFFFFFFFFu;
            ack.variant       = ACK;
            ack.plainSize     = hdr.plainSize;
            ack.encryptedSize = 0;
            ack.totalPairs    = hdr.totalPairs;
            ack.totalTests    = hdr.totalTests;
            ack.testIndex     = hdr.testIndex;

            char ackBuf[sizeof(PacketHeader)];
            std::memcpy(ackBuf, &ack, sizeof(ack));
            int sent = sendto(sock, ackBuf, (int)sizeof(ackBuf), 0, (sockaddr*)&src, srclen);
            if(sent < 0) perror("sendto ACK"); else std::cout << "ACK sent for test " << currentTest << '\n';

            // If last test already finalized (expectedPairs==0 from timeout) exit
            if(currentTest == totalTests && expectedPairs == 0 && !testActive) break;
            continue; // Do not treat control as data
        }

        // Ignore data before any control
        if(currentTest == 0){
            std::cout << "Data before control; ignoring." << std::endl;
            continue;
        }

        // Timeout check for incomplete test
        if(receivedPlain < expectedPairs || receivedEncrypted < expectedPairs){
            uint64_t elapsedSec = (recvUs - testStartUs) / 1000000ull;
            if(elapsedSec > (uint64_t)testTimeoutSec){
                std::cout << "Test " << currentTest << " timeout after " << elapsedSec
                          << "s. Finalizing partial results and waiting for next control." << std::endl;
                // Persist partial data
                if(!metrics.empty()){
                    std::string fn = "data/server_metrics_t" + std::to_string(currentTest) + ".csv";
                    write_server_csv(fn, metrics);
                    metrics.clear();
                }
                // Mark test inactive; ignore further data until next control
                testActive = false;
                testTimedOut = true;
                expectedPairs = 0;
                continue; // Do not record this late packet
            }
        }

        // Ignore packets for other tests (until their control arrives)
        if(hdr.testIndex != (uint32_t)currentTest){
            std::cout << "Out-of-test data packet testIndex=" << hdr.testIndex
                      << " current=" << currentTest << " ignored" << std::endl;
            continue;
        }

        // Record metrics
        ReceiveMetrics rm{};
        rm.pairId        = hdr.pairId;
        rm.variant       = hdr.variant;
        rm.plainSize     = hdr.plainSize;
        rm.encryptedSize = hdr.encryptedSize;
        rm.recvTsUs      = recvUs;
        rm.payloadBytes  = (uint32_t)(n - sizeof(PacketHeader));
        metrics.push_back(rm);
        if(hdr.variant == PLAIN)      ++receivedPlain;
        else if(hdr.variant == ENCRYPTED) ++receivedEncrypted;

        std::cout << "Test " << currentTest << " recv pairId=" << hdr.pairId
                  << " variant=" << (int)hdr.variant
                  << " (" << receivedPlain << "/" << expectedPairs << " plain, "
                  << receivedEncrypted << "/" << expectedPairs << " enc)" << std::endl;

        // Completion condition
        if(expectedPairs > 0 && receivedPlain >= expectedPairs && receivedEncrypted >= expectedPairs){
            std::cout << "Test " << currentTest << " complete." << std::endl;
            if(!metrics.empty()){
                std::string fn = "data/server_metrics_t" + std::to_string(currentTest) + ".csv";
                write_server_csv(fn, metrics);
                metrics.clear();
            }
            testActive = false;
            expectedPairs = 0;
            if(currentTest == totalTests){
                std::cout << "All tests done" << std::endl;
                break;
            }
            // Wait for next control; ignore interim data until control arrives
        }
    }

    close(sock);
    return 0;
}
#endif // __linux__