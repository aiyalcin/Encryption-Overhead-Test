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
// Linux / POSIX networking + OpenSSL
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#else
// Windows / other platform stub so the project still builds.
int main() { std::cout << "Client Linux implementation only. Run under Linux." << std::endl; return 0; }
#endif

#ifdef __linux__
// -----------------------------------------------------------------------------
// Protocol definitions
// -----------------------------------------------------------------------------
static const uint32_t HEADER_MAGIC = 0x504B5450u; // 'PKTP'
// Variants: added HASHED (4) and ENC_HASHED (5) for hashing only and combined
// encryption+hash tests.
enum Variant : uint8_t { PLAIN = 0, ENCRYPTED = 1, CONTROL = 2, ACK = 3, HASHED = 4, ENC_HASHED = 5 };

#pragma pack(push,1)
struct PacketHeader {
    uint32_t magic;        // HEADER_MAGIC
    uint32_t pairId;       // Pair index (0xFFFFFFFF for control / ack)
    uint8_t  variant;      // Variant code
    uint8_t  reserved[3];  // Padding
    uint32_t plainSize;    // Size of original plaintext
    uint32_t encryptedSize;// Size of transformed extra payload (encrypted bytes and/or hash bytes)
    uint32_t totalPairs;   // Total pairs in test (CONTROL / ACK)
    uint32_t totalTests;   // Total number of tests (CONTROL / ACK)
    uint32_t testIndex;    // 1-based test index
};
#pragma pack(pop)

// Minimal per-packet send metrics (client side)
struct SendMetrics {
    uint32_t pairId;
    uint8_t  variant;      // Packet type
    uint64_t sendTsUs;     // Timestamp (system_clock, microseconds)
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

// Encryption without duration logging
static std::vector<char> encrypt_payload(const std::vector<char>& plain, RSA* rsa) {
    if (!rsa) { return {}; }
    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> out(rsaSize);
    int encLen = RSA_public_encrypt((int)plain.size(), reinterpret_cast<const unsigned char*>(plain.data()), out.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (encLen == -1) {
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        return {};
    }
    return std::vector<char>(out.begin(), out.begin() + encLen);
}

// Hashing without duration logging
static std::vector<unsigned char> hash_payload(const std::vector<char>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int dlen = 0;
    if (!ctx || !md ||
        !EVP_DigestInit_ex(ctx, md, nullptr) ||
        !EVP_DigestUpdate(ctx, data.data(), data.size()) ||
        !EVP_DigestFinal_ex(ctx, digest.data(), &dlen)) {
        std::cerr << "Hashing failed" << std::endl;
        dlen = 0;
    }
    EVP_MD_CTX_free(ctx);
    digest.resize(dlen);
    return digest;
}

static void write_client_csv(const std::string& path, const std::vector<SendMetrics>& rows) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if (!out.is_open()) {
        std::cerr << "Failed to open metrics file: " << path << "\n";
        return;
    }
    out << "pair_id,variant,send_ts_us\n";
    for (auto const& r : rows) {
        out << r.pairId << ','
            << (int)r.variant << ','
            << r.sendTsUs << '\n';
    }
}

static uint64_t nowMicros() {
    auto t = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()).count();
}

static bool send_datagram(int sock, const sockaddr_in& dest, const char* data, size_t len,
                          uint64_t& sendTsUs) {
    long sent = sendto(sock, data, (int)len, 0, (const sockaddr*)&dest, sizeof(dest));
    if (sent < 0) {
        perror("sendto");
        sendTsUs = 0;
        return false;
    }
    sendTsUs = nowMicros();
    return true;
}

static inline bool send_datagram(int sock, const sockaddr_in& dest, const char* data, size_t len) {
    uint64_t ts; // intentionally discarded
    return send_datagram(sock, dest, data, len, ts);
}

static bool wait_for_ack(int sock, int expectedTest, int expectedTotalTests, int timeoutMs) {
    fd_set rfds; FD_ZERO(&rfds); FD_SET(sock, &rfds);
    timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
    int rc = select(sock + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0) return false; // timeout or error

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
    // Configuration (defaults updated for 3 test modes)
    int port = 8080;
    int pairCount = 50;
    int plaintextBits = 1024;
    int totalTests = 3; // 1: encryption, 2: hashing, 3: enc+hash
    std::string targetIP;

    std::cout << "Target IP (default 127.0.0.1): ";
    if (!(std::cin >> targetIP) || targetIP.empty()) targetIP = "127.0.0.1";

    std::cout << "Pairs per test (default 50): ";
    if (!(std::cin >> pairCount) || pairCount <= 0) pairCount = 50;

    std::cout << "Number of tests (default 3 - enc, hash, enc+hash): ";
    if (!(std::cin >> totalTests) || totalTests <= 0) totalTests = 3;

    size_t plainSizeBytes = plaintextBits / 8;
    std::cout << "Running " << totalTests << " tests (mode per test), each with "
              << pairCount << " pairs." << std::endl;

    // Load public key (encryption only used if key loads)
    RSA* rsa = load_public_key("Keys/public.pem");

    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(targetIP.c_str());

    // Iterate tests (each test uses a different transformation mode)
    for (int testIndex = 1; testIndex <= totalTests; ++testIndex) {
        Variant modeVariant = ENCRYPTED;
        if (testIndex == 2) modeVariant = HASHED;
        else if (testIndex == 3) modeVariant = ENC_HASHED;

        std::string modeName = (modeVariant == ENCRYPTED ? "ENCRYPTION" :
                               (modeVariant == HASHED ? "HASHING" : "ENCRYPT+HASH"));
        std::cout << "\n--- Test " << testIndex << "/" << totalTests
                  << " Mode=" << modeName << " ---" << std::endl;

        // Handshake control with retry
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

            send_datagram(sock, dest, reinterpret_cast<char*>(&ctrl), sizeof(ctrl));
            std::cout << "Sent CONTROL (attempt " << attempt << ") waiting ACK..." << std::endl;
            acked = wait_for_ack(sock, testIndex, totalTests, 2000);
            if (!acked) {
                std::cout << "ACK timeout" << (attempt < maxRetries ? ", retrying..." : "; giving up") << std::endl;
            }
        }
        if (!acked) {
            std::cerr << "Skipping test " << testIndex << " (no ACK)." << std::endl;
            continue;
        }
        std::cout << "ACK received. Sending pairs..." << std::endl;

        std::vector<SendMetrics> metrics;
        metrics.reserve(pairCount * 2);

        // Send pairs (plain + transformed)
        for (int pairId = 0; pairId < pairCount; ++pairId) {
            auto plain = generate_payload(plainSizeBytes);

            // Plain packet
            PacketHeader hPlain{};
            hPlain.magic         = HEADER_MAGIC;
            hPlain.pairId        = (uint32_t)pairId;
            hPlain.variant       = PLAIN;
            hPlain.plainSize     = (uint32_t)plain.size();
            hPlain.encryptedSize = 0;
            hPlain.totalPairs    = 0;
            hPlain.totalTests    = (uint32_t)totalTests;
            hPlain.testIndex     = (uint32_t)testIndex;

            std::vector<char> bufPlain(sizeof(hPlain) + plain.size());
            std::memcpy(bufPlain.data(), &hPlain, sizeof(hPlain));
            std::memcpy(bufPlain.data() + sizeof(hPlain), plain.data(), plain.size());
            uint64_t sendPlainTsUs = 0;
            send_datagram(sock, dest, bufPlain.data(), bufPlain.size(), sendPlainTsUs);
            metrics.push_back({ (uint32_t)pairId, PLAIN, sendPlainTsUs });
            std::cout << "Sent packet pairId=" << pairId << " variant=" << (int)PLAIN << " ts_us=" << sendPlainTsUs << std::endl;

            // Transformation depending on test mode
            std::vector<char> transformed;

            if (modeVariant == ENCRYPTED) {
                auto enc = encrypt_payload(plain, rsa);
                transformed = enc;
            } else if (modeVariant == HASHED) {
                auto digest = hash_payload(plain);
                transformed.assign((char*)digest.data(), (char*)digest.data() + digest.size());
            } else if (modeVariant == ENC_HASHED) {
                auto enc = encrypt_payload(plain, rsa);
                auto digest = hash_payload(plain);
                transformed.reserve(enc.size() + digest.size());
                transformed.insert(transformed.end(), enc.begin(), enc.end());
                transformed.insert(transformed.end(), (char*)digest.data(), (char*)digest.data() + digest.size());
            }

            // Transformed packet header
            PacketHeader hTrans{};
            hTrans.magic         = HEADER_MAGIC;
            hTrans.pairId        = (uint32_t)pairId;
            hTrans.variant       = modeVariant;
            hTrans.plainSize     = (uint32_t)plain.size();
            hTrans.encryptedSize = (uint32_t)transformed.size();
            hTrans.totalPairs    = 0;
            hTrans.totalTests    = (uint32_t)totalTests;
            hTrans.testIndex     = (uint32_t)testIndex;

            std::vector<char> bufTrans(sizeof(hTrans) + transformed.size());
            std::memcpy(bufTrans.data(), &hTrans, sizeof(hTrans));
            if (!transformed.empty()) {
                std::memcpy(bufTrans.data() + sizeof(hTrans), transformed.data(), transformed.size());
            }
            uint64_t sendTransTsUs = 0;
            send_datagram(sock, dest, bufTrans.data(), bufTrans.size(), sendTransTsUs);
            metrics.push_back({ (uint32_t)pairId, modeVariant, sendTransTsUs });
            std::cout << "Sent packet pairId=" << pairId << " variant=" << (int)modeVariant << " ts_us=" << sendTransTsUs << std::endl;
        }

        // Persist metrics for this test
        std::string fileName = "data/client_metrics_t" + std::to_string(testIndex) + ".csv";
        write_client_csv(fileName, metrics);

        // Skip pacing logic after final test
        if (testIndex == totalTests) continue;

        // Optional pacing ACK wait for next test start
        const int maxPaceRetries = 3;
        for (int attempt = 1; attempt <= maxPaceRetries; ++attempt) {
            std::cout << "Waiting for next ACK (attempt " << attempt << ")..." << std::flush;
            bool gotAck = wait_for_ack(sock, testIndex + 1, totalTests, 2000);
            if (gotAck) {
                std::cout << "ACK received." << std::endl;
                break;
            }
            std::cout << "no ACK, resending CONTROL..." << std::endl;

            PacketHeader ctrl{};
            ctrl.magic        = HEADER_MAGIC;
            ctrl.pairId       = 0xFFFFFFFFu;
            ctrl.variant      = CONTROL;
            ctrl.plainSize    = (uint32_t)plainSizeBytes;
            ctrl.encryptedSize= 0;
            ctrl.totalPairs   = (uint32_t)pairCount;
            ctrl.totalTests   = (uint32_t)totalTests;
            ctrl.testIndex    = (uint32_t)testIndex + 1; // next test

            send_datagram(sock, dest, reinterpret_cast<char*>(&ctrl), sizeof(ctrl));
            std::cout << "Resent CONTROL, waiting ACK..." << std::endl;
            bool ack = wait_for_ack(sock, testIndex + 1, totalTests, 2000);
            if (ack) {
                std::cout << "ACK received after resend." << std::endl;
                break;
            }
        }
    }

    // Cleanup
    if (rsa) RSA_free(rsa);
    close(sock);
    std::cout << "All requested tests processed." << std::endl;
    return 0;
}
#endif // __linux__