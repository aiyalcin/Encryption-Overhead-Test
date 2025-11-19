#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <limits>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <fstream>
#include <chrono>
#include <random>

std::string loadFile(const char* path) {
    std::ifstream f(path);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

unsigned short checksum(unsigned short* buf, int len)
{
    unsigned long sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

bool check_server(const std::string& targetIP, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(targetIP.c_str());
    bool connected = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    return connected;
}

struct PacketMetrics {
    int id;
    bool encrypted;
    size_t plainSize;
    size_t encryptedSize;
    uint64_t encryptDurationNs;
    uint64_t sendDurationNs;
    uint64_t sendTimestampUs;
};

static std::mt19937 g_rng{ std::random_device{}() };

std::vector<char> generate_random_data(int length)
{
    static const char letters[] = "abcdefghijklmnopqrstuvwxyz";
    std::uniform_int_distribution<int> dist(0, 25);
    std::vector<char> data;
    data.reserve(length);
    for (int i = 0; i < length; ++i) data.push_back(letters[dist(g_rng)]);
    return data;
}

RSA* load_public_key_once(const std::string& path)
{
    std::string publicKeyStr = loadFile(path.c_str());
    BIO* bio = BIO_new_mem_buf(publicKeyStr.data(), (int)publicKeyStr.size());
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        std::cerr << "Failed to load public key: " << path << "\n";
        exit(1);
    }
    return rsa;
}

std::vector<char> encrypt_data(const std::vector<char>& data, RSA* rsa, uint64_t& durationNs)
{
    auto t0 = std::chrono::steady_clock::now();
    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> encryptedBuffer(rsaSize);
    int len = RSA_public_encrypt((int)data.size(), reinterpret_cast<const unsigned char*>(data.data()), encryptedBuffer.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    auto t1 = std::chrono::steady_clock::now();
    durationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    if (len == -1) {
        std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        durationNs = 0;
        return {};
    }
    return std::vector<char>(encryptedBuffer.begin(), encryptedBuffer.begin() + len);
}

void send_data_raw(const std::vector<char>& payload, const std::string& targetIP, const std::string& localIP, int port, uint64_t& sendDurationNs, uint64_t& timestampUs)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return; }
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) { perror("setsockopt"); close(sock); return; }
    char packetBuf[4096];
    memset(packetBuf, 0, sizeof(packetBuf));
    struct iphdr* ip = (struct iphdr*)packetBuf;
    struct udphdr* udp = (struct udphdr*)(packetBuf + sizeof(struct iphdr));
    char* pktPayload = packetBuf + sizeof(struct iphdr) + sizeof(struct udphdr);
    int payloadLen = (int)payload.size();
    memcpy(pktPayload, payload.data(), payloadLen);
    ip->ihl = 5; ip->version = 4; ip->tos = 0; ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payloadLen);
    ip->id = htons(54321); ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(localIP.c_str()); ip->daddr = inet_addr(targetIP.c_str());
    ip->check = checksum((unsigned short*)ip, sizeof(struct iphdr));
    udp->source = htons(5555); udp->dest = htons(port); udp->len = htons(sizeof(struct udphdr) + payloadLen); udp->check = 0;
    struct sockaddr_in dest {}; dest.sin_family = AF_INET; dest.sin_addr.s_addr = inet_addr(targetIP.c_str());
    int packetLen = sizeof(struct iphdr) + sizeof(struct udphdr) + payloadLen;
    auto t0 = std::chrono::steady_clock::now();
    if (sendto(sock, packetBuf, packetLen, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) { perror("sendto"); sendDurationNs = 0; timestampUs = 0; }
    else {
        auto t1 = std::chrono::steady_clock::now();
        sendDurationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(t1.time_since_epoch()).count();
    }
    close(sock);
}

void send_control_packet(int encryptedCount, int plainCount, int port, const std::string& targetIP, const std::string& localIP)
{
    std::string controlStr = "CONTROL " + std::to_string(encryptedCount) + " " + std::to_string(plainCount);
    std::vector<char> payload(controlStr.begin(), controlStr.end());
    uint64_t sendNs=0, tsUs=0;
    send_data_raw(payload, targetIP, localIP, port, sendNs, tsUs);
    std::cout << "Control packet sent: " << controlStr << "\n";
}

void get_input(int& dataPacketSizeBits, int& portNumber, std::string& TargetIPAdress, int& amountOfIterations)
{
    std::cout << "Please enter data packet size in bits (default & max 1024): ";
    if (!(std::cin >> dataPacketSizeBits) || dataPacketSizeBits <= 0 || dataPacketSizeBits > 1024) { std::cout << "Invalid input. Using default 1024 bits.\n"; dataPacketSizeBits = 1024; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }
    std::cout << "Please enter port number (default 8080): ";
    if (!(std::cin >> portNumber) || portNumber <= 0) { portNumber = 8080; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }
    std::cout << "Please enter target IP address (default xxx.xxx.xxx.xxx): ";
    if (!(std::cin >> TargetIPAdress)) { TargetIPAdress = ""; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }
    std::cout << "How many iterations? (default 50): ";
    if (!(std::cin >> amountOfIterations)) { amountOfIterations = 50; std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); }
}

void run_phase(bool encrypt, int bytesPerPacket, int port, int iterations, const std::string& targetIP, const std::string& localIP, RSA* rsa, std::vector<PacketMetrics>& outMetrics)
{
    std::cout << (encrypt ? "\n--- Phase: Encrypted ---\n" : "\n--- Phase: Plain ---\n");
    outMetrics.reserve(outMetrics.size() + iterations);
    for (int i = 0; i < iterations; ++i) {
        PacketMetrics m{}; m.id = i; m.encrypted = encrypt; m.plainSize = bytesPerPacket; m.encryptDurationNs = 0; m.encryptedSize = bytesPerPacket;
        std::vector<char> plain = generate_random_data(bytesPerPacket);
        std::vector<char> toSend;
        if (encrypt) {
            toSend = encrypt_data(plain, rsa, m.encryptDurationNs);
            m.encryptedSize = toSend.size();
        } else {
            toSend = plain;
        }
        uint64_t sendNs = 0, tsUs = 0;
        send_data_raw(toSend, targetIP, localIP, port, sendNs, tsUs);
        m.sendDurationNs = sendNs; m.sendTimestampUs = tsUs;
        outMetrics.push_back(m);
        std::cout << "Packet " << (i + 1) << "/" << iterations << " sent. enc=" << (encrypt?"1":"0") << " encSize=" << m.encryptedSize << " encNs=" << m.encryptDurationNs << " sendNs=" << m.sendDurationNs << "\n";
    }
}

void save_metrics_csv(const std::string& filePath, const std::vector<PacketMetrics>& metrics)
{
    std::ofstream out(filePath);
    if (!out.is_open()) { std::cerr << "Failed to open metrics file: " << filePath << "\n"; return; }
    out << "id,encrypted,plain_size,encrypted_size,encrypt_ns,send_ns,send_timestamp_us\n";
    for (auto const& m : metrics) {
        out << m.id << ',' << (m.encrypted?1:0) << ',' << m.plainSize << ',' << m.encryptedSize << ',' << m.encryptDurationNs << ',' << m.sendDurationNs << ',' << m.sendTimestampUs << '\n';
    }
    std::cout << "Saved metrics: " << metrics.size() << " rows to " << filePath << "\n";
}

void start_test(int& dataPacketSizeBits, int& portNumber, int& amountOfIterations, std::string& targetIPAdress, std::string& localIPAdress)
{
    std::cout << "Starting step 1 - Testing server connection\n";
    std::cout << "Checking if server is online...\n";
    if (!check_server(targetIPAdress, portNumber)) { std::cerr << "Server not reachable. Aborting.\n"; exit(0); }
    std::cout << "Server is online.\n============ STEP 1 COMPLETED ============\n";

    RSA* rsa = load_public_key_once("Keys/public.pem");
    int bytesPerPacket = dataPacketSizeBits / 8;
    std::vector<PacketMetrics> metrics;

    // Send control packet so receiver knows counts
    send_control_packet(amountOfIterations, amountOfIterations, portNumber, targetIPAdress, localIPAdress);

    for (int i = 0; i < std::min(5, amountOfIterations); ++i) {
        uint64_t dummyEncNs = 0; auto plain = generate_random_data(bytesPerPacket); encrypt_data(plain, rsa, dummyEncNs); uint64_t sNs=0, ts=0; send_data_raw(plain, targetIPAdress, localIPAdress, portNumber, sNs, ts); }

    run_phase(true, bytesPerPacket, portNumber, amountOfIterations, targetIPAdress, localIPAdress, rsa, metrics);
    run_phase(false, bytesPerPacket, portNumber, amountOfIterations, targetIPAdress, localIPAdress, rsa, metrics);

    std::cout << "\nTest complete. Total packets measured: " << metrics.size() << " (" << amountOfIterations << " encrypted + " << amountOfIterations << " plain).\n";
    save_metrics_csv("overhead_metrics.csv", metrics);
    RSA_free(rsa);
}

int main()
{
    int dataPacketSizeBits = 1024;
    int portNumber = 8080;
    int amountOfIterations = 50;
    std::string targetIPAdress;
    std::string localIPAress = "145.49.32.123";
    get_input(dataPacketSizeBits, portNumber, targetIPAdress, amountOfIterations);
    std::cout << "Using packet size: " << dataPacketSizeBits << " bits\n";
    std::cout << "Using port: " << portNumber << "\n";
    std::cout << "Target IP: " << (targetIPAdress.empty()?"(none)":targetIPAdress) << "\n";
    std::cout << "Local IP: " << localIPAress << "\n";
    std::cout << "Iterations per phase: " << amountOfIterations << "\n";
    start_test(std::ref(dataPacketSizeBits), std::ref(portNumber), std::ref(amountOfIterations), std::ref(targetIPAdress), std::ref(localIPAress));
    return 0;
}}