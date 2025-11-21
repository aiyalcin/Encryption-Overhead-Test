#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <random>
#include <cstdint>
#include <cstring>
#include <filesystem>

#ifdef __linux__
// Linux / POSIX + OpenSSL headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#else
// Windows placeholder so project can compile in VS; real logic runs on Linux.
#pragma warning(disable:4996)
int main(){ std::cout<<"Client Linux implementation only. Run under Linux."<<std::endl; return 0; }
#endif

#ifdef __linux__
// -----------------------------------------------------------------------------
// Protocol definitions
// -----------------------------------------------------------------------------
// Magic constant 'PKTP' identifying packet headers
static const uint32_t HEADER_MAGIC = 0x504B5450u; // 'PKTP'

// Packet variant codes:
// 0 = plain payload
// 1 = encrypted payload
// 2 = control (start test, announces parameters)
// 3 = ack (server acknowledges control)
enum Variant : uint8_t { PLAIN = 0, ENCRYPTED = 1, CONTROL = 2, ACK = 3 };

#pragma pack(push,1)
struct PacketHeader {
    uint32_t magic;        // HEADER_MAGIC
    uint32_t pairId;       // For data: pair index. 0xFFFFFFFF for control / ack.
    uint8_t  variant;      // See Variant enum
    uint8_t  reserved[3];  // Padding / alignment
    uint32_t plainSize;    // For data: size of original plaintext. For control: configured plaintext size.
    uint32_t encryptedSize;// Size of encrypted payload (0 for plain/control/ack)
    uint32_t totalPairs;   // Pairs per test (only meaningful in CONTROL / ACK)
    uint32_t totalTests;   // Total number of tests (CONTROL / ACK)
    uint32_t testIndex;    // 1-based test index (CONTROL / ACK). Echoed in data packets.
};
#pragma pack(pop)

// Metrics recorded client-side per sent packet
struct SendMetrics {
    uint32_t pairId;
    uint8_t  variant;       // 0 plain, 1 encrypted
    uint32_t plainSize;
    uint32_t encryptedSize;
    uint64_t encryptNs;     // Encryption duration (ns), 0 for plain
    uint64_t sendNs;        // sendto() duration (ns)
    uint64_t sendTsUs;      // Send timestamp (microseconds since steady_clock epoch)
};

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------
static std::string loadFile(const std::string& path) {
    std::ifstream f(path);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static RSA* load_public_key(const std::string& path) {
    std::string pem = loadFile(path);
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        std::cerr << "Failed to load public key: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        std::exit(1);
    }
    return rsa;
}

static std::vector<char> generate_payload(size_t size) {
    static std::mt19937 rng{ std::random_device{}() };
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<char> data(size);
    for (auto& c : data) c = static_cast<char>(dist(rng));
    return data;
}

static std::vector<char> encrypt_payload(const std::vector<char>& plain, RSA* rsa, uint64_t& durationNs) {
    auto t0 = std::chrono::steady_clock::now();
    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> out(rsaSize);
    int encLen = RSA_public_encrypt((int)plain.size(), reinterpret_cast<const unsigned char*>(plain.data()), out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    auto t1 = std::chrono::steady_clock::now();
    durationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    if (encLen == -1) {
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        durationNs = 0;
        return {};
    }
    return std::vector<char>(out.begin(), out.begin() + encLen);
}

static void write_client_csv(const std::string& path, const std::vector<SendMetrics>& rows) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "Failed to open metrics file: " << path << "\n";
        return;
    }
    out << "pair_id,variant,plain_size,encrypted_size,encrypt_ns,send_ns,send_ts_us\n";
    for (auto const& r : rows) {
        out << r.pairId << ','
            << (int)r.variant << ','
            << r.plainSize << ','
            << r.encryptedSize << ','
            << r.encryptNs << ','
            << r.sendNs << ','
            << r.sendTsUs << '\n';
    }
}

static uint64_t nowMicros() {
    auto t = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()).count();
}

static bool send_datagram(int sock, const sockaddr_in& dest, const char* data, size_t len, uint64_t& sendNs, uint64_t& sendTsUs) {
    auto t0 = std::chrono::steady_clock::now();
    long sent = sendto(sock, data, (int)len, 0, (const sockaddr*)&dest, sizeof(dest));
    auto t1 = std::chrono::steady_clock::now();
    if (sent < 0) {
        perror("sendto");
        sendNs = 0; sendTsUs = 0;
        return false;
    }
    sendNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    sendTsUs = nowMicros();
    return true;
}

// Wait for an ACK packet matching expected test and total tests (with timeout)
static bool wait_for_ack(int sock, int expectedTest, int expectedTotalTests, int timeoutMs) {
    fd_set rfds; FD_ZERO(&rfds); FD_SET(sock, &rfds);
    timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
    int rc = select(sock + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0) return false; // timeout / error

    char buf[sizeof(PacketHeader)];
    sockaddr_in src{}; socklen_t sl = sizeof(src);
    int n = recvfrom(sock, buf, (int)sizeof(buf), 0, (sockaddr*)&src, &sl);
    if (n < (int)sizeof(PacketHeader)) return false;

    PacketHeader hdr; std::memcpy(&hdr, buf, sizeof(hdr));
    if (hdr.magic != HEADER_MAGIC || hdr.variant != ACK) return false;
    if ((int)hdr.testIndex != expectedTest || (int)hdr.totalTests != expectedTotalTests) return false;
    return true;
}

// -----------------------------------------------------------------------------
// Main program
// -----------------------------------------------------------------------------
int main() {
    // User configuration
    int port = 8080;
    int pairCount = 50;
    int plaintextBits = 1024;
    int totalTests = 1;
    std::string targetIP;

    std::cout << "Target IP (default 127.0.0.1): ";
    if (!(std::cin >> targetIP) || targetIP.empty()) targetIP = "127.0.0.1";

    std::cout << "UDP Port (default 8080): ";
    if (!(std::cin >> port) || port <= 0) port = 8080;

    std::cout << "Pairs per test (default 50): ";
    if (!(std::cin >> pairCount) || pairCount <= 0) pairCount = 50;

    std::cout << "Plaintext size bits (default 1024 max 1024): ";
    if (!(std::cin >> plaintextBits) || plaintextBits <= 0 || plaintextBits > 1024) plaintextBits = 1024;

    std::cout << "Number of tests (default 1): ";
    if (!(std::cin >> totalTests) || totalTests <= 0) totalTests = 1;

    size_t plainSizeBytes = plaintextBits / 8;
    std::cout << "Running " << totalTests << " tests, each with " << pairCount << " pairs (plain + encrypted).\n";

    // Load encryption key
    RSA* rsa = load_public_key("Keys/public.pem");

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(targetIP.c_str());

    // Iterate tests
    for (int testIndex = 1; testIndex <= totalTests; ++testIndex) {
        std::cout << "\n--- Test " << testIndex << "/" << totalTests << " ---" << std::endl;

        // Handshake: send control and wait for ACK (retry)
        const int maxRetries = 5;
        bool acked = false;
        for (int attempt = 1; attempt <= maxRetries && !acked; ++attempt) {
            PacketHeader ctrl{};
            ctrl.magic        = HEADER_MAGIC;
            ctrl.pairId       = 0xFFFFFFFFu;
            ctrl.variant      = CONTROL;
            ctrl.plainSize    = (uint32_t)plainSizeBytes;
            ctrl.encryptedSize= 0;
            ctrl.totalPairs   = (uint32_t)pairCount;
            ctrl.totalTests   = (uint32_t)totalTests;
            ctrl.testIndex    = (uint32_t)testIndex;

            uint64_t sns=0, sts=0;
            send_datagram(sock, dest, reinterpret_cast<char*>(&ctrl), sizeof(ctrl), sns, sts);
            std::cout << "Sent CONTROL (attempt " << attempt << ") waiting ACK..." << std::endl;
            acked = wait_for_ack(sock, testIndex, totalTests, 2000); // 2s timeout
            if (!acked) {
                std::cout << "ACK timeout" << (attempt < maxRetries ? ", retrying..." : "; giving up") << std::endl;
            }
        }
        if (!acked) {
            std::cerr << "Skipping test " << testIndex << " (no ACK)." << std::endl;
            continue;
        }
        std::cout << "ACK received. Sending packet pairs..." << std::endl;

        std::vector<SendMetrics> metrics;
        metrics.reserve(pairCount * 2);

        // Send packet pairs
        for (int pairId = 0; pairId < pairCount; ++pairId) {
            auto plain = generate_payload(plainSizeBytes);

            // Encrypted payload
            uint64_t encNs = 0;
            auto encrypted = encrypt_payload(plain, rsa, encNs);

            // Plain packet header
            PacketHeader hPlain{};
            hPlain.magic        = HEADER_MAGIC;
            hPlain.pairId       = (uint32_t)pairId;
            hPlain.variant      = PLAIN;
            hPlain.plainSize    = (uint32_t)plain.size();
            hPlain.encryptedSize= 0;
            hPlain.totalPairs   = 0;
            hPlain.totalTests   = (uint32_t)totalTests;
            hPlain.testIndex    = (uint32_t)testIndex;

            std::vector<char> bufPlain(sizeof(hPlain) + plain.size());
            std::memcpy(bufPlain.data(), &hPlain, sizeof(hPlain));
            std::memcpy(bufPlain.data() + sizeof(hPlain), plain.data(), plain.size());
            uint64_t sendPlainNs=0, sendPlainTsUs=0;
            send_datagram(sock, dest, bufPlain.data(), bufPlain.size(), sendPlainNs, sendPlainTsUs);
            metrics.push_back({ (uint32_t)pairId, PLAIN, (uint32_t)plain.size(), 0, 0, sendPlainNs, sendPlainTsUs });

            // Encrypted packet header
            PacketHeader hEnc{};
            hEnc.magic         = HEADER_MAGIC;
            hEnc.pairId        = (uint32_t)pairId;
            hEnc.variant       = ENCRYPTED;
            hEnc.plainSize     = (uint32_t)plain.size();
            hEnc.encryptedSize = (uint32_t)encrypted.size();
            hEnc.totalPairs    = 0;
            hEnc.totalTests    = (uint32_t)totalTests;
            hEnc.testIndex     = (uint32_t)testIndex;

            std::vector<char> bufEnc(sizeof(hEnc) + encrypted.size());
            std::memcpy(bufEnc.data(), &hEnc, sizeof(hEnc));
            if (!encrypted.empty()) {
                std::memcpy(bufEnc.data() + sizeof(hEnc), encrypted.data(), encrypted.size());
            }
            uint64_t sendEncNs=0, sendEncTsUs=0;
            send_datagram(sock, dest, bufEnc.data(), bufEnc.size(), sendEncNs, sendEncTsUs);
            metrics.push_back({ (uint32_t)pairId, ENCRYPTED, (uint32_t)plain.size(), (uint32_t)encrypted.size(), encNs, sendEncNs, sendEncTsUs });

            std::cout << "Pair " << (pairId + 1) << "/" << pairCount
                      << " plain=" << plain.size()
                      << " enc=" << encrypted.size()
                      << " encNs=" << encNs << std::endl;
        }

        // Write per-test metrics
        std::string fileName = "data/client_metrics_t" + std::to_string(testIndex) + ".csv";
        write_client_csv(fileName, metrics);

        // --- WAIT FOR NEXT ACK OR TIMEOUT / RESEND CONTROL LOGIC HERE (STUB) ---
        // Simple approach: after finishing a test, wait for next ack of next control;
        // ensure not to start new test until ack received (already enforced).
        // Optional pacing and detection stub; no change needed for next test start logic
        // as it already waits for ack.

        // ----------

        // Optional: Basic pacing / retry detection (stub, not fully robust)
        const int maxPaceRetries = 3;
        for (int attempt = 1; attempt <= maxPaceRetries; ++attempt) {
            std::cout << "Waiting for next ACK (attempt " << attempt << ")..." << std::flush;
            bool gotAck = wait_for_ack(sock, testIndex + 1, totalTests, 2000);
            if (gotAck) {
                std::cout << "ACK received." << std::endl;
                break;
            }
            std::cout << "no ACK, resending CONTROL..." << std::endl;

            // Resend control packet (same as initial handshake)
            PacketHeader ctrl{};
            ctrl.magic        = HEADER_MAGIC;
            ctrl.pairId       = 0xFFFFFFFFu;
            ctrl.variant      = CONTROL;
            ctrl.plainSize    = (uint32_t)plainSizeBytes;
            ctrl.encryptedSize= 0;
            ctrl.totalPairs   = (uint32_t)pairCount;
            ctrl.totalTests   = (uint32_t)totalTests;
            ctrl.testIndex    = (uint32_t)testIndex;

            uint64_t sns=0, sts=0;
            send_datagram(sock, dest, reinterpret_cast<char*>(&ctrl), sizeof(ctrl), sns, sts);
            std::cout << "Resent CONTROL, waiting ACK..." << std::endl;
            wait_for_ack(sock, testIndex, totalTests, 2000); // Wait for ACK (implicit retry limit)
        }
    }

    // Cleanup
    if (rsa) RSA_free(rsa);
    close(sock);
    std::cout << "All requested tests processed." << std::endl;
    return 0;
}
#endif // __linux__