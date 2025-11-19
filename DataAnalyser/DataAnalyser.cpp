// DataAnalyser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <unordered_map>

struct ClientRow {
    int id{};
    bool encrypted{};
    size_t plainSize{};
    size_t encryptedSize{};
    uint64_t encryptNs{};
    uint64_t sendNs{};
    uint64_t sendTsUs{}; // microseconds since epoch
    bool parsed{false};
};

struct ServerRow {
    int id{};
    bool encrypted{};
    size_t sizeBytes{};
    uint64_t recvTsUs{};
    bool parsed{false};
};

struct Combined {
    int id{};
    bool encrypted{};
    size_t plainSize{};
    size_t encryptedSize{};
    size_t serverSize{};
    uint64_t encryptNs{};
    uint64_t sendNs{};
    uint64_t sendTsUs{};
    uint64_t recvTsUs{};
    int64_t latencyUs{}; // recv - send
    uint32_t invalidFlags{}; // bitmask
    std::string reasons;
};

enum InvalidBits : uint32_t {
    MISSING_CLIENT          = 1u << 0,
    MISSING_SERVER          = 1u << 1,
    FLAG_MISMATCH           = 1u << 2,
    SIZE_MISMATCH           = 1u << 3,
    NEGATIVE_LATENCY        = 1u << 4,
    ZERO_SIZE               = 1u << 5,
    ZERO_ENCRYPT_TIME       = 1u << 6,
    ZERO_SEND_TIME          = 1u << 7,
    DUPLICATE_ID_CLIENT     = 1u << 8,
    DUPLICATE_ID_SERVER     = 1u << 9,
    OUTLIER_LATENCY         = 1u << 10
};

static std::vector<std::string> splitCSV(const std::string& line) {
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, ',')) parts.push_back(item);
    return parts;
}

static bool toUInt64(const std::string& s, uint64_t& v) { try { v = static_cast<uint64_t>(std::stoull(s)); return true; } catch (...) { return false; } }
static bool toSize(const std::string& s, size_t& v) { try { v = static_cast<size_t>(std::stoull(s)); return true; } catch (...) { return false; } }
static bool toInt(const std::string& s, int& v) { try { v = std::stoi(s); return true; } catch (...) { return false; } }

std::vector<ClientRow> loadClient(const std::string& path) {
    std::ifstream in(path);
    std::vector<ClientRow> rows;
    if (!in.is_open()) { std::cerr << "Failed to open client CSV: " << path << "\n"; return rows; }
    std::string line; bool header = true; std::unordered_map<int,int> idCount;
    while (std::getline(in, line)) {
        if (line.empty()) continue; if (header) { header = false; continue; }
        auto cols = splitCSV(line); if (cols.size() != 7) continue;
        ClientRow r; int encInt;
        if (!toInt(cols[0], r.id)) continue;
        if (!toInt(cols[1], encInt)) continue; r.encrypted = (encInt == 1);
        if (!toSize(cols[2], r.plainSize)) continue;
        if (!toSize(cols[3], r.encryptedSize)) continue;
        if (!toUInt64(cols[4], r.encryptNs)) continue;
        if (!toUInt64(cols[5], r.sendNs)) continue;
        if (!toUInt64(cols[6], r.sendTsUs)) continue;
        r.parsed = true; idCount[r.id]++;
        rows.push_back(r);
    }
    // Mark duplicates by setting sendNs=0 (will flag) not altering structure, flags handled later
    return rows;
}

std::vector<ServerRow> loadServer(const std::string& path) {
    std::ifstream in(path);
    std::vector<ServerRow> rows;
    if (!in.is_open()) { std::cerr << "Failed to open server CSV: " << path << "\n"; return rows; }
    std::string line; bool header = true; std::unordered_map<int,int> idCount;
    while (std::getline(in, line)) {
        if (line.empty()) continue; if (header) { header = false; continue; }
        auto cols = splitCSV(line); if (cols.size() != 4) continue;
        ServerRow r; int encInt;
        if (!toInt(cols[0], r.id)) continue;
        if (!toInt(cols[1], encInt)) continue; r.encrypted = (encInt == 1);
        if (!toSize(cols[2], r.sizeBytes)) continue;
        if (!toUInt64(cols[3], r.recvTsUs)) continue;
        r.parsed = true; idCount[r.id]++;
        rows.push_back(r);
    }
    return rows;
}

void markDuplicates(const std::vector<ClientRow>& client, const std::vector<ServerRow>& server,
                    std::unordered_map<int,uint32_t>& clientFlags,
                    std::unordered_map<int,uint32_t>& serverFlags) {
    std::unordered_map<int,int> countsC; for (auto& c : client) countsC[c.id]++;
    for (auto& kv : countsC) if (kv.second > 1) clientFlags[kv.first] |= DUPLICATE_ID_CLIENT;
    std::unordered_map<int,int> countsS; for (auto& s : server) countsS[s.id]++;
    for (auto& kv : countsS) if (kv.second > 1) serverFlags[kv.first] |= DUPLICATE_ID_SERVER;
}

std::vector<Combined> mergeAndValidate(const std::vector<ClientRow>& client, const std::vector<ServerRow>& server) {
    std::unordered_map<int, ClientRow> cMap; for (auto const& c : client) if (c.parsed) cMap[c.id] = c;
    std::unordered_map<int, ServerRow> sMap; for (auto const& s : server) if (s.parsed) sMap[s.id] = s;
    std::unordered_map<int,uint32_t> cFlags; std::unordered_map<int,uint32_t> sFlags; markDuplicates(client, server, cFlags, sFlags);

    std::unordered_map<int,bool> allIds; for (auto& c : client) allIds[c.id] = true; for (auto& s : server) allIds[s.id] = true;
    std::vector<Combined> out; out.reserve(allIds.size());

    for (auto& kv : allIds) {
        int id = kv.first; Combined comb{}; comb.id = id;
        bool hasC = cMap.find(id) != cMap.end(); bool hasS = sMap.find(id) != sMap.end();
        if (!hasC) comb.invalidFlags |= MISSING_CLIENT; if (!hasS) comb.invalidFlags |= MISSING_SERVER;
        if (hasC) {
            const auto& c = cMap[id]; comb.encrypted = c.encrypted; comb.plainSize = c.plainSize; comb.encryptedSize = c.encryptedSize;
            comb.encryptNs = c.encryptNs; comb.sendNs = c.sendNs; comb.sendTsUs = c.sendTsUs;
            if (cFlags.count(id)) comb.invalidFlags |= cFlags[id];
            if (c.encrypted && c.encryptNs == 0) comb.invalidFlags |= ZERO_ENCRYPT_TIME;
            if (c.sendNs == 0) comb.invalidFlags |= ZERO_SEND_TIME;
            if (!c.encrypted && c.encryptedSize != c.plainSize) comb.invalidFlags |= SIZE_MISMATCH;
            if ((c.encrypted ? c.encryptedSize : c.plainSize) == 0) comb.invalidFlags |= ZERO_SIZE;
        }
        if (hasS) { const auto& s = sMap[id]; comb.serverSize = s.sizeBytes; comb.recvTsUs = s.recvTsUs; if (sFlags.count(id)) comb.invalidFlags |= sFlags[id]; }
        if (hasC && hasS) {
            size_t expectedSentSize = comb.encrypted ? comb.encryptedSize : comb.plainSize;
            if (expectedSentSize != comb.serverSize) comb.invalidFlags |= SIZE_MISMATCH;
            comb.latencyUs = static_cast<int64_t>(comb.recvTsUs) - static_cast<int64_t>(comb.sendTsUs);
            if (comb.latencyUs < 0) comb.invalidFlags |= NEGATIVE_LATENCY;
        }
        out.push_back(comb);
    }
    return out;
}

void detectLatencyOutliers(std::vector<Combined>& rows) {
    std::vector<int64_t> latencies; latencies.reserve(rows.size());
    for (auto& r : rows) if ((r.invalidFlags & (MISSING_CLIENT | MISSING_SERVER | NEGATIVE_LATENCY)) == 0) latencies.push_back(r.latencyUs);
    if (latencies.size() < 8) return;
    std::vector<int64_t> tmp = latencies; std::nth_element(tmp.begin(), tmp.begin() + tmp.size()/2, tmp.end()); double median = (double)tmp[tmp.size()/2];
    std::vector<double> dev; dev.reserve(latencies.size()); for (auto v : latencies) dev.push_back(std::abs(v - median));
    std::nth_element(dev.begin(), dev.begin() + dev.size()/2, dev.end()); double mad = dev[dev.size()/2]; if (mad < 1) mad = 1; double threshold = 6.0 * mad;
    for (auto& r : rows) {
        if (r.invalidFlags) continue; double diff = std::abs((double)r.latencyUs - median); if (diff > threshold) r.invalidFlags |= OUTLIER_LATENCY;
    }
}

void assembleReasons(std::vector<Combined>& rows) {
    for (auto& r : rows) {
        std::vector<std::string> reasons;
        if (r.invalidFlags & MISSING_CLIENT) reasons.emplace_back("missing_client");
        if (r.invalidFlags & MISSING_SERVER) reasons.emplace_back("missing_server");
        if (r.invalidFlags & FLAG_MISMATCH) reasons.emplace_back("flag_mismatch");
        if (r.invalidFlags & SIZE_MISMATCH) reasons.emplace_back("size_mismatch");
        if (r.invalidFlags & NEGATIVE_LATENCY) reasons.emplace_back("negative_latency");
        if (r.invalidFlags & ZERO_SIZE) reasons.emplace_back("zero_size");
        if (r.invalidFlags & ZERO_ENCRYPT_TIME) reasons.emplace_back("zero_encrypt_time");
        if (r.invalidFlags & ZERO_SEND_TIME) reasons.emplace_back("zero_send_time");
        if (r.invalidFlags & DUPLICATE_ID_CLIENT) reasons.emplace_back("duplicate_id_client");
        if (r.invalidFlags & DUPLICATE_ID_SERVER) reasons.emplace_back("duplicate_id_server");
        if (r.invalidFlags & OUTLIER_LATENCY) reasons.emplace_back("outlier_latency");
        r.reasons.clear(); for (size_t i=0;i<reasons.size();++i) { if (i) r.reasons += ';'; r.reasons += reasons[i]; }
    }
}

struct Stats { double count{}; double min{}; double max{}; double mean{}; double stddev{}; double median{}; };

Stats computeStats(const std::vector<int64_t>& values) {
    Stats s{}; if (values.empty()) return s; s.count = (double)values.size();
    s.min = (double)*std::min_element(values.begin(), values.end()); s.max = (double)*std::max_element(values.begin(), values.end());
    double sum=0; for (auto v:values) sum+=v; s.mean=sum/s.count; std::vector<int64_t> tmp=values; std::nth_element(tmp.begin(), tmp.begin()+tmp.size()/2, tmp.end()); s.median=(double)tmp[tmp.size()/2];
    double acc=0; for (auto v:values){ double d=v - s.mean; acc += d*d; } s.stddev = std::sqrt(acc / s.count); return s;
}

void writeOutputs(const std::vector<Combined>& rows) {
    std::ofstream validOut("filtered_results.csv"); std::ofstream invalidOut("invalid_results.csv");
    if (!validOut.is_open() || !invalidOut.is_open()) { std::cerr << "Failed opening output CSV files.\n"; return; }
    validOut << "id,encrypted,plain_size,encrypted_size,server_size,encrypt_ns,send_ns,send_ts_us,recv_ts_us,latency_us\n";
    invalidOut << "id,encrypted,plain_size,encrypted_size,server_size,encrypt_ns,send_ns,send_ts_us,recv_ts_us,latency_us,invalid_flags,reasons\n";
    std::vector<int64_t> latEnc, latPlain;
    for (auto const& r : rows) {
        if (r.invalidFlags == 0) {
            validOut << r.id << ',' << (r.encrypted?1:0) << ',' << r.plainSize << ',' << r.encryptedSize << ',' << r.serverSize << ',' << r.encryptNs << ',' << r.sendNs << ',' << r.sendTsUs << ',' << r.recvTsUs << ',' << r.latencyUs << '\n';
            (r.encrypted ? latEnc : latPlain).push_back(r.latencyUs);
        } else {
            invalidOut << r.id << ',' << (r.encrypted?1:0) << ',' << r.plainSize << ',' << r.encryptedSize << ',' << r.serverSize << ',' << r.encryptNs << ',' << r.sendNs << ',' << r.sendTsUs << ',' << r.recvTsUs << ',' << r.latencyUs << ',' << r.invalidFlags << ',' << r.reasons << '\n';
        }
    }
    Stats sEnc = computeStats(latEnc); Stats sPlain = computeStats(latPlain);
    std::ofstream summary("summary.txt");
    if (summary.is_open()) {
        summary << "Valid encrypted packets: " << (int)sEnc.count << "\n";
        summary << "Encrypted latency (us): min=" << sEnc.min << " max=" << sEnc.max << " mean=" << sEnc.mean << " median=" << sEnc.median << " stddev=" << sEnc.stddev << "\n\n";
        summary << "Valid plain packets: " << (int)sPlain.count << "\n";
        summary << "Plain latency (us): min=" << sPlain.min << " max=" << sPlain.max << " mean=" << sPlain.mean << " median=" << sPlain.median << " stddev=" << sPlain.stddev << "\n\n";
        summary << "Latency delta mean (enc - plain): " << (sEnc.mean - sPlain.mean) << " us\n";
        summary << "Latency delta median (enc - plain): " << (sEnc.median - sPlain.median) << " us\n";
    }
}

int main(int argc, char* argv[]) {
    std::string clientPath = "overhead_metrics.csv";
    std::string serverPath = "received_packets.csv";
    if (argc > 1) clientPath = argv[1];
    if (argc > 2) serverPath = argv[2];
    std::cout << "Loading client metrics from: " << clientPath << "\n";
    auto clientRows = loadClient(clientPath); std::cout << "Client rows parsed: " << clientRows.size() << "\n";
    std::cout << "Loading server metrics from: " << serverPath << "\n";
    auto serverRows = loadServer(serverPath); std::cout << "Server rows parsed: " << serverRows.size() << "\n";
    auto merged = mergeAndValidate(clientRows, serverRows); detectLatencyOutliers(merged); assembleReasons(merged); writeOutputs(merged);
    std::cout << "Analysis complete. See filtered_results.csv, invalid_results.csv, summary.txt\n";
    return 0;
}
