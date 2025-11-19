#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <random>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// Header magic constant 'PKTP'
static const uint32_t HEADER_MAGIC = 0x504B5450u;

// Packet variant codes
// 0 = plain, 1 = encrypted, 2 = control
enum Variant : uint8_t { PLAIN = 0, ENCRYPTED = 1, CONTROL = 2 };

#pragma pack(push,1)
struct PacketHeader {
    uint32_t magic;        // HEADER_MAGIC
    uint32_t pairId;       // pair identifier
    uint8_t  variant;      // Variant code
    uint8_t  reserved[3];  // padding
    uint32_t plainSize;    // size of original plaintext
    uint32_t encryptedSize;// size of encrypted payload (0 if plain/control)
    uint32_t totalPairs;   // only meaningful for CONTROL, else 0
};
#pragma pack(pop)

struct SendMetrics {
    uint32_t pairId;
    uint8_t variant; // 0 plain 1 encrypted
    uint32_t plainSize;
    uint32_t encryptedSize;
    uint64_t encryptNs; // 0 for plain
    uint64_t sendNs;
    uint64_t sendTsUs; // microseconds since steady_clock epoch
};

std::string loadFile(const std::string& path) {
    std::ifstream f(path);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

RSA* load_public_key(const std::string& path) {
    std::string pem = loadFile(path);
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        std::cerr << "Failed to load public key. OpenSSL error: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        std::exit(1);
    }
    return rsa;
}

std::vector<char> generate_payload(size_t size) {
    static std::mt19937 rng{ std::random_device{}() };
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<char> data(size);
    for (auto& c : data) c = static_cast<char>(dist(rng));
    return data;
}

std::vector<char> encrypt_payload(const std::vector<char>& plain, RSA* rsa, uint64_t& durationNs) {
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

void write_client_csv(const std::string& path, const std::vector<SendMetrics>& rows) {
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if (!out.is_open()) { std::cerr << "Failed to open metrics file: " << path << "\n"; return; }
    out << "pair_id,variant,plain_size,encrypted_size,encrypt_ns,send_ns,send_ts_us\n";
    for (auto const& r : rows) {
        out << r.pairId << ',' << (int)r.variant << ',' << r.plainSize << ',' << r.encryptedSize << ','
            << r.encryptNs << ',' << r.sendNs << ',' << r.sendTsUs << '\n';
    }
    std::cout << "Client metrics saved: " << rows.size() << " entries to " << path << "\n";
}

bool send_datagram(int sock, const sockaddr_in& dest, const char* data, size_t len, uint64_t& sendNs, uint64_t& sendTsUs) {
    auto t0 = std::chrono::steady_clock::now();
    ssize_t sent = sendto(sock, data, len, 0, (const sockaddr*)&dest, sizeof(dest));
    auto t1 = std::chrono::steady_clock::now();
    if (sent < 0) { perror("sendto"); sendNs = 0; sendTsUs = 0; return false; }
    sendNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    sendTsUs = std::chrono::duration_cast<std::chrono::microseconds>(t1.time_since_epoch()).count();
    return true;
}

int main() {
    int port = 8080;
    int pairCount = 50;
    int plaintextBits = 1024; // user input bits
    std::string targetIP;
    std::string localIP = "127.0.0.1"; // set to appropriate local IP if needed

    std::cout << "Target IP (default 127.0.0.1): ";
    if (!(std::cin >> targetIP) || targetIP.empty()) targetIP = "127.0.0.1";
    std::cout << "UDP Port (default 8080): ";
    if (!(std::cin >> port) || port <= 0) port = 8080;
    std::cout << "Number of pairs (default 50): ";
    if (!(std::cin >> pairCount) || pairCount <= 0) pairCount = 50;
    std::cout << "Plaintext size bits (default 1024, max 1024): ";
    if (!(std::cin >> plaintextBits) || plaintextBits <= 0 || plaintextBits > 1024) plaintextBits = 1024;

    size_t plainSizeBytes = plaintextBits / 8;

    std::cout << "Preparing to send " << pairCount << " pairs (plain + encrypted).\n";

    // Load RSA public key once
    RSA* rsa = load_public_key("Keys/public.pem");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    sockaddr_in dest{}; dest.sin_family = AF_INET; dest.sin_port = htons(port); dest.sin_addr.s_addr = inet_addr(targetIP.c_str());

    std::vector<SendMetrics> metrics; metrics.reserve(pairCount * 2 + 1);

    // Send control packet
    PacketHeader ctrl{}; ctrl.magic = HEADER_MAGIC; ctrl.pairId = 0xFFFFFFFFu; ctrl.variant = CONTROL; ctrl.plainSize = (uint32_t)plainSizeBytes; ctrl.encryptedSize = 0; ctrl.totalPairs = (uint32_t)pairCount;
    uint64_t sendNs=0, sendTsUs=0;
    send_datagram(sock, dest, reinterpret_cast<char*>(&ctrl), sizeof(ctrl), sendNs, sendTsUs);
    std::cout << "Control packet sent.\n";

    for (int pairId = 0; pairId < pairCount; ++pairId) {
        // Generate plain payload once
        std::vector<char> plain = generate_payload(plainSizeBytes);

        // Encrypt copy
        uint64_t encNs = 0;
        std::vector<char> encrypted = encrypt_payload(plain, rsa, encNs);

        // Prepare and send plain datagram
        PacketHeader hPlain{}; hPlain.magic = HEADER_MAGIC; hPlain.pairId = (uint32_t)pairId; hPlain.variant = PLAIN; hPlain.plainSize = (uint32_t)plain.size(); hPlain.encryptedSize = 0; hPlain.totalPairs = 0;
        std::vector<char> bufferPlain(sizeof(hPlain) + plain.size());
        std::memcpy(bufferPlain.data(), &hPlain, sizeof(hPlain));
        std::memcpy(bufferPlain.data() + sizeof(hPlain), plain.data(), plain.size());
        uint64_t sendPlainNs=0, sendPlainTsUs=0;
        send_datagram(sock, dest, bufferPlain.data(), bufferPlain.size(), sendPlainNs, sendPlainTsUs);
        metrics.push_back({ (uint32_t)pairId, PLAIN, (uint32_t)plain.size(), 0, 0, sendPlainNs, sendPlainTsUs });

        // Prepare and send encrypted datagram
        PacketHeader hEnc{}; hEnc.magic = HEADER_MAGIC; hEnc.pairId = (uint32_t)pairId; hEnc.variant = ENCRYPTED; hEnc.plainSize = (uint32_t)plain.size(); hEnc.encryptedSize = (uint32_t)encrypted.size(); hEnc.totalPairs = 0;
        std::vector<char> bufferEnc(sizeof(hEnc) + encrypted.size());
        std::memcpy(bufferEnc.data(), &hEnc, sizeof(hEnc));
        if (!encrypted.empty()) std::memcpy(bufferEnc.data() + sizeof(hEnc), encrypted.data(), encrypted.size());
        uint64_t sendEncNs=0, sendEncTsUs=0;
        send_datagram(sock, dest, bufferEnc.data(), bufferEnc.size(), sendEncNs, sendEncTsUs);
        metrics.push_back({ (uint32_t)pairId, ENCRYPTED, (uint32_t)plain.size(), (uint32_t)encrypted.size(), encNs, sendEncNs, sendEncTsUs });

        std::cout << "Pair " << pairId+1 << "/" << pairCount << " sent. Plain bytes=" << plain.size() << ", Encrypted bytes=" << encrypted.size() << ", encNs=" << encNs << "\n";
    }

    write_client_csv("data/client_metrics.csv", metrics);

    RSA_free(rsa);
    close(sock);
    return 0;
}