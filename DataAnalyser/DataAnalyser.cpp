#include <algorithm>
#include <cstdint>
#include <cmath>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>

// Multi-test data analyser. Usage: DataAnalyser <num_tests> (optional).
// It will read data/client_metrics_tX.csv and data/server_metrics_tX.csv for X=1..num_tests.
// If num_tests not provided, it auto-detects sequentially starting from 1.

// -----------------------------------------------------------------------------
// CSV column definitions
// Client CSV: pair_id, variant(0 plain 1 encrypted), plain_size, encrypted_size,
//             encrypt_ns, send_ns, send_ts_us
// Server CSV: pair_id, variant, plain_size, encrypted_size, recv_ts_us, payload_bytes
// ---------------------------------------------------------------------------->

// Represents a parsed row from the client metrics CSV
struct ClientRow {
    uint32_t pairId{};
    uint8_t  variant{};            // 0 = plain, 1 = encrypted
    uint32_t plainSize{};
    uint32_t encryptedSize{};
    uint64_t encryptNs{};          // encryption duration in ns
    uint64_t sendNs{};             // time spent preparing/sending in ns (client side)
    uint64_t sendTsUs{};           // send timestamp (microseconds epoch or monotonic)
    bool     parsed{false};
};

// Represents a parsed row from the server metrics CSV
struct ServerRow {
    uint32_t pairId{};
    uint8_t  variant{};            // 0 = plain, 1 = encrypted
    uint32_t plainSize{};
    uint32_t encryptedSize{};
    uint64_t recvTsUs{};           // receive timestamp in microseconds
    uint32_t payloadBytes{};       // raw payload bytes actually received
    bool     parsed{false};
};

// Aggregated metrics combining client + server rows for the same pairId
struct PairMetrics {
    uint32_t pairId{};

    // Plain message metrics
    uint64_t plainSendTsUs{};
    uint64_t plainRecvTsUs{};
    int64_t  plainLatencyUs{};     // recv - send
    uint64_t plainSendNs{};        // send overhead (client)
    uint32_t plainSize{};          // size of plain message

    // Encrypted message metrics
    uint64_t encSendTsUs{};
    uint64_t encRecvTsUs{};
    int64_t  encLatencyUs{};       // recv - send (encrypted variant)
    uint64_t encSendNs{};
    uint32_t encPlainSize{};       // original plain size before encryption
    uint32_t encEncryptedSize{};   // size after encryption
    uint64_t encEncryptNs{};       // encryption duration

    // Validation / flagging
    uint32_t    invalidFlags{};    // bit mask of InvalidBits
    std::string reasons;           // human-readable concatenated reasons

    // Derived delta (encrypted - plain)
    int64_t latencyDeltaUs{};
};

// Bit mask flags identifying invalid or outlier conditions
enum InvalidBits : uint32_t {
    MISSING_PLAIN_SEND      = 1u << 0,
    MISSING_ENC_SEND        = 1u << 1,
    MISSING_PLAIN_RECV      = 1u << 2,
    MISSING_ENC_RECV        = 1u << 3,
    SIZE_MISMATCH_PLAIN     = 1u << 4,
    SIZE_MISMATCH_ENC       = 1u << 5,
    ENCRYPT_SIZE_INVALID    = 1u << 6,
    NEGATIVE_LAT_PLAIN      = 1u << 7,
    NEGATIVE_LAT_ENC        = 1u << 8,
    ZERO_ENCRYPT_TIME       = 1u << 9,
    OUTLIER_LATENCY_PLAIN   = 1u << 10,
    OUTLIER_LATENCY_ENC     = 1u << 11,
    OUTLIER_DELTA           = 1u << 12
};

// -----------------------------------------------------------------------------
// Parsing utilities
// ---------------------------------------------------------------------------->
static std::vector<std::string> splitCSV(const std::string& line) {
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, ',')) {
        parts.push_back(item);
    }
    return parts;
}

static bool toUInt32(const std::string& s, uint32_t& v) {
    try { v = static_cast<uint32_t>(std::stoul(s)); return true; } catch (...) { return false; }
}
static bool toUInt64(const std::string& s, uint64_t& v) {
    try { v = static_cast<uint64_t>(std::stoull(s)); return true; } catch (...) { return false; }
}
static bool toInt(const std::string& s, int& v) {
    try { v = std::stoi(s); return true; } catch (...) { return false; }
}

// -----------------------------------------------------------------------------
// Row parsing helpers
// ---------------------------------------------------------------------------->
static ClientRow parseClientRow(const std::vector<std::string>& cols) {
    ClientRow r; if (cols.size() != 7) return r;
    int var{};
    if (!toUInt32(cols[0], r.pairId)) return r;
    if (!toInt(cols[1], var)) return r; r.variant = static_cast<uint8_t>(var);
    if (!toUInt32(cols[2], r.plainSize)) return r;
    if (!toUInt32(cols[3], r.encryptedSize)) return r;
    if (!toUInt64(cols[4], r.encryptNs)) return r;
    if (!toUInt64(cols[5], r.sendNs)) return r;
    if (!toUInt64(cols[6], r.sendTsUs)) return r;
    r.parsed = true; return r;
}

static ServerRow parseServerRow(const std::vector<std::string>& cols) {
    ServerRow r; if (cols.size() != 6) return r;
    int var{};
    if (!toUInt32(cols[0], r.pairId)) return r;
    if (!toInt(cols[1], var)) return r; r.variant = static_cast<uint8_t>(var);
    if (!toUInt32(cols[2], r.plainSize)) return r;
    if (!toUInt32(cols[3], r.encryptedSize)) return r;
    if (!toUInt64(cols[4], r.recvTsUs)) return r;
    if (!toUInt32(cols[5], r.payloadBytes)) return r;
    r.parsed = true; return r;
}

// -----------------------------------------------------------------------------
// CSV file loaders
// ---------------------------------------------------------------------------->
static std::vector<ClientRow> loadClient(const std::string& path) {
    std::ifstream in(path); std::vector<ClientRow> rows;
    if (!in.is_open()) { std::cerr << "Failed open client: " << path << '\n'; return rows; }
    std::string line; bool header = true;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (header) { header = false; continue; }
        ClientRow r = parseClientRow(splitCSV(line));
        if (r.parsed) rows.push_back(r);
    }
    return rows;
}

static std::vector<ServerRow> loadServer(const std::string& path) {
    std::ifstream in(path); std::vector<ServerRow> rows;
    if (!in.is_open()) { std::cerr << "Failed open server: " << path << '\n'; return rows; }
    std::string line; bool header = true;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (header) { header = false; continue; }
        ServerRow r = parseServerRow(splitCSV(line));
        if (r.parsed) rows.push_back(r);
    }
    return rows;
}

// -----------------------------------------------------------------------------
// Pair construction
// ---------------------------------------------------------------------------->
static void buildPairs(const std::vector<ClientRow>& cRows,
                       const std::vector<ServerRow>& sRows,
                       std::vector<PairMetrics>& out) {
    std::unordered_map<uint64_t, ClientRow> cPlain, cEnc;
    std::unordered_map<uint64_t, ServerRow> sPlain, sEnc;

    for (const auto& c : cRows) {
        if (!c.parsed) continue;
        if (c.variant == 0) cPlain[c.pairId] = c; else if (c.variant == 1) cEnc[c.pairId] = c;
    }
    for (const auto& s : sRows) {
        if (!s.parsed) continue;
        if (s.variant == 0) sPlain[s.pairId] = s; else if (s.variant == 1) sEnc[s.pairId] = s;
    }

    std::unordered_map<uint64_t, bool> ids;
    for (auto& keyValue : cPlain) ids[keyValue.first] = true;
    for (auto& keyValue : cEnc)   ids[keyValue.first] = true;
    for (auto& keyValue : sPlain) ids[keyValue.first] = true;
    for (auto& keyValue : sEnc)   ids[keyValue.first] = true;

    out.reserve(ids.size());

    for (auto& keyValue : ids) {
        uint64_t id = keyValue.first; PairMetrics pairMetrics{}; pairMetrics.pairId = static_cast<uint32_t>(id);
        bool hcP = cPlain.count(id) != 0;
        bool hcE = cEnc.count(id)   != 0;
        bool hsP = sPlain.count(id) != 0;
        bool hsE = sEnc.count(id)   != 0;

        // Plain send data
        if (hcP) {
            const auto& c = cPlain[id];
            pairMetrics.plainSendTsUs = c.sendTsUs;
            pairMetrics.plainSendNs   = c.sendNs;
            pairMetrics.plainSize     = c.plainSize;
        } else {
            pairMetrics.invalidFlags |= MISSING_PLAIN_SEND;
        }

        // Encrypted send data
        if (hcE) {
            const auto& c = cEnc[id];
            pairMetrics.encSendTsUs      = c.sendTsUs;
            pairMetrics.encSendNs        = c.sendNs;
            pairMetrics.encPlainSize     = c.plainSize;
            pairMetrics.encEncryptedSize = c.encryptedSize;
            pairMetrics.encEncryptNs     = c.encryptNs;
        } else {
            pairMetrics.invalidFlags |= MISSING_ENC_SEND;
        }

        // Receive timestamps
        if (hsP) {
            pairMetrics.plainRecvTsUs = sPlain[id].recvTsUs;
        } else {
            pairMetrics.invalidFlags |= MISSING_PLAIN_RECV;
        }
        if (hsE) {
            pairMetrics.encRecvTsUs = sEnc[id].recvTsUs;
        } else {
            pairMetrics.invalidFlags |= MISSING_ENC_RECV;
        }

        // Latencies and validations
        if (hcP && hsP) {
            pairMetrics.plainLatencyUs = static_cast<int64_t>(pairMetrics.plainRecvTsUs) - static_cast<int64_t>(pairMetrics.plainSendTsUs);
            if (pairMetrics.plainLatencyUs < 0) pairMetrics.invalidFlags |= NEGATIVE_LAT_PLAIN;
            if (pairMetrics.plainSize == 0)     pairMetrics.invalidFlags |= SIZE_MISMATCH_PLAIN;
        }
        if (hcE && hsE) {
            pairMetrics.encLatencyUs = static_cast<int64_t>(pairMetrics.encRecvTsUs) - static_cast<int64_t>(pairMetrics.encSendTsUs);
            if (pairMetrics.encLatencyUs < 0) pairMetrics.invalidFlags |= NEGATIVE_LAT_ENC;
            if (pairMetrics.encEncryptedSize == 0 || pairMetrics.encPlainSize == 0) {
                pairMetrics.invalidFlags |= ENCRYPT_SIZE_INVALID;
            } else if (pairMetrics.encEncryptedSize < pairMetrics.encPlainSize) {
                pairMetrics.invalidFlags |= SIZE_MISMATCH_ENC;
            }
            if (pairMetrics.encEncryptNs == 0) pairMetrics.invalidFlags |= ZERO_ENCRYPT_TIME;
        }
        if (hcP && hcE) {
            pairMetrics.latencyDeltaUs = pairMetrics.encLatencyUs - pairMetrics.plainLatencyUs;
        }
        out.push_back(pairMetrics);
    }
}

// -----------------------------------------------------------------------------
// Outlier detection
// ---------------------------------------------------------------------------->
static double medianOf(const std::vector<int64_t>& values) {
    if (values.empty()) return 0.0;
    std::vector<int64_t> tmp = values;
    std::nth_element(tmp.begin(), tmp.begin() + tmp.size() / 2, tmp.end());
    return static_cast<double>(tmp[tmp.size() / 2]);
}

template <typename Getter>
static void markOutliers(std::vector<PairMetrics>& rows,
                         const std::vector<int64_t>& values,
                         uint32_t flag,
                         Getter getter) {
    if (values.size() < 8) return; // need enough samples for robust MAD
    double med = medianOf(values);
    std::vector<double> dev; dev.reserve(values.size());
    for (auto v : values) dev.push_back(std::abs(static_cast<double>(v) - med));
    std::nth_element(dev.begin(), dev.begin() + dev.size() / 2, dev.end());
    double mad = dev[dev.size() / 2]; if (mad < 1.0) mad = 1.0; // avoid zero threshold
    double threshold = 6.0 * mad; // robust outlier threshold
    for (auto& r : rows) {
        double val = static_cast<double>(getter(r));
        if (val > 0) {
            double diff = std::abs(val - med);
            if (diff > threshold) r.invalidFlags |= flag;
        }
    }
}

static void detectOutliers(std::vector<PairMetrics>& rows) {
    std::vector<int64_t> plainL, encL, deltas;
    plainL.reserve(rows.size()); encL.reserve(rows.size()); deltas.reserve(rows.size());
    for (auto& r : rows) {
        bool plainValid = !(r.invalidFlags & (MISSING_PLAIN_SEND | MISSING_PLAIN_RECV | NEGATIVE_LAT_PLAIN)) && r.plainLatencyUs > 0;
        bool encValid   = !(r.invalidFlags & (MISSING_ENC_SEND   | MISSING_ENC_RECV   | NEGATIVE_LAT_ENC))   && r.encLatencyUs   > 0;
        if (plainValid) plainL.push_back(r.plainLatencyUs);
        if (encValid)   encL.push_back(r.encLatencyUs);
        if (r.invalidFlags == 0 && r.plainLatencyUs > 0 && r.encLatencyUs > 0) deltas.push_back(r.latencyDeltaUs);
    }
    markOutliers(rows, plainL, OUTLIER_LATENCY_PLAIN, [](const PairMetrics& r){ return r.plainLatencyUs; });
    markOutliers(rows, encL,   OUTLIER_LATENCY_ENC,   [](const PairMetrics& r){ return r.encLatencyUs;   });
    markOutliers(rows, deltas, OUTLIER_DELTA,         [](const PairMetrics& r){ return r.latencyDeltaUs; });
}

// -----------------------------------------------------------------------------
// Reason assembly
// ---------------------------------------------------------------------------->
static void assembleReasons(std::vector<PairMetrics>& rows) {
    struct Map { uint32_t bit; const char* text; };
    static const Map map[] = {
        { MISSING_PLAIN_SEND,    "missing_plain_send" },
        { MISSING_ENC_SEND,      "missing_enc_send" },
        { MISSING_PLAIN_RECV,    "missing_plain_recv" },
        { MISSING_ENC_RECV,      "missing_enc_recv" },
        { SIZE_MISMATCH_PLAIN,   "size_mismatch_plain" },
        { SIZE_MISMATCH_ENC,     "size_mismatch_enc" },
        { ENCRYPT_SIZE_INVALID,  "encrypt_size_invalid" },
        { NEGATIVE_LAT_PLAIN,    "negative_latency_plain" },
        { NEGATIVE_LAT_ENC,      "negative_latency_enc" },
        { ZERO_ENCRYPT_TIME,     "zero_encrypt_time" },
        { OUTLIER_LATENCY_PLAIN, "outlier_latency_plain" },
        { OUTLIER_LATENCY_ENC,   "outlier_latency_enc" },
        { OUTLIER_DELTA,         "outlier_delta" }
    };

    for (auto& r : rows) {
        if (r.invalidFlags == 0) { r.reasons.clear(); continue; }
        std::string joined; bool first = true;
        for (const auto& m : map) {
            if (r.invalidFlags & m.bit) {
                if (!first) joined.push_back(';');
                joined.append(m.text); first = false;
            }
        }
        r.reasons = std::move(joined);
    }
}

// -----------------------------------------------------------------------------
// Statistics computation
// ---------------------------------------------------------------------------->
struct Stats { double count{}; double min{}; double max{}; double mean{}; double median{}; double stddev{}; };

static Stats computeStats(const std::vector<int64_t>& v) {
    Stats s; if (v.empty()) return s;
    s.count = static_cast<double>(v.size());
    s.min   = static_cast<double>(*std::min_element(v.begin(), v.end()));
    s.max   = static_cast<double>(*std::max_element(v.begin(), v.end()));
    double sum = 0.0; for (auto x : v) sum += static_cast<double>(x); s.mean = sum / s.count;
    std::vector<int64_t> tmp = v; std::nth_element(tmp.begin(), tmp.begin() + tmp.size()/2, tmp.end()); s.median = static_cast<double>(tmp[tmp.size()/2]);
    double acc = 0.0; for (auto x : v) { double d = static_cast<double>(x) - s.mean; acc += d*d; } s.stddev = std::sqrt(acc / s.count);
    return s;
}

// -----------------------------------------------------------------------------
// Output writers
// ---------------------------------------------------------------------------->
static void writeOutputs(const std::vector<PairMetrics>& rows) {
    std::ofstream valid("paired_filtered.csv");
    std::ofstream invalid("paired_invalid.csv");
    std::ofstream summary("paired_summary.txt");
    if (!valid.is_open() || !invalid.is_open()) { std::cerr << "Failed open output files" << std::endl; return; }

    valid   << "pair_id,plain_latency_us,enc_latency_us,latency_delta_us,plain_size,enc_plain_size,enc_encrypted_size,encrypt_ns,plain_send_ns,enc_send_ns\n";
    invalid << "pair_id,plain_latency_us,enc_latency_us,latency_delta_us,invalid_flags,reasons\n";

    std::vector<int64_t> plainL, encL, deltaL;
    for (const auto& r : rows) {
        if (r.invalidFlags == 0) {
            valid << r.pairId << ','
                  << r.plainLatencyUs << ','
                  << r.encLatencyUs << ','
                  << r.latencyDeltaUs << ','
                  << r.plainSize << ','
                  << r.encPlainSize << ','
                  << r.encEncryptedSize << ','
                  << r.encEncryptNs << ','
                  << r.plainSendNs << ','
                  << r.encSendNs << '\n';
            if (r.plainLatencyUs > 0) plainL.push_back(r.plainLatencyUs);
            if (r.encLatencyUs > 0)   encL.push_back(r.encLatencyUs);
            if (r.latencyDeltaUs)     deltaL.push_back(r.latencyDeltaUs);
        } else {
            invalid << r.pairId << ','
                    << r.plainLatencyUs << ','
                    << r.encLatencyUs << ','
                    << r.latencyDeltaUs << ','
                    << r.invalidFlags << ','
                    << r.reasons << '\n';
        }
    }

    Stats sp = computeStats(plainL), se = computeStats(encL), sd = computeStats(deltaL);
    if (summary.is_open()) {
        summary << "Valid pairs: " << static_cast<int>(sp.count) << '\n';
        summary << "Plain latency us: min=" << sp.min << " max=" << sp.max << " mean=" << sp.mean << " median=" << sp.median << " stddev=" << sp.stddev << '\n';
        summary << "Encrypted latency us: min=" << se.min << " max=" << se.max << " mean=" << se.mean << " median=" << se.median << " stddev=" << se.stddev << '\n';
        summary << "Delta (enc-plain) us: min=" << sd.min << " max=" << sd.max << " mean=" << sd.mean << " median=" << sd.median << " stddev=" << sd.stddev << '\n';
        summary << "Mean overhead (enc - plain): " << (se.mean - sp.mean) << " us\n";
    }
}

static void writeTestSummary(std::ofstream& summary,int t,const std::vector<PairMetrics>& rows){
    std::vector<int64_t> plainL,encL,deltaL;
    for(auto&r:rows){
        if(r.invalidFlags==0){
            if(r.plainLatencyUs>0) plainL.push_back(r.plainLatencyUs);
            if(r.encLatencyUs>0) encL.push_back(r.encLatencyUs);
            if(r.latencyDeltaUs) deltaL.push_back(r.latencyDeltaUs);
        }
    }
    Stats sp=computeStats(plainL), se=computeStats(encL), sd=computeStats(deltaL);
    summary<<"Test "<<t<<": valid_pairs="<<(int)sp.count<<"\n";
    summary<<"  Plain latency us: min="<<sp.min<<" max="<<sp.max<<" mean="<<sp.mean<<" median="<<sp.median<<" stddev="<<sp.stddev<<"\n";
    summary<<"  Encrypted latency us: min="<<se.min<<" max="<<se.max<<" mean="<<se.mean<<" median="<<se.median<<" stddev="<<se.stddev<<"\n";
    summary<<"  Delta (enc-plain) us: min="<<sd.min<<" max="<<sd.max<<" mean="<<sd.mean<<" median="<<sd.median<<" stddev="<<sd.stddev<<"\n";
    summary<<"  Mean overhead (enc - plain): "<<(se.mean - sp.mean)<<" us\n\n";
}

// -----------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------->
int main(int argc,char* argv[]) {
    int tests=0;
    if(argc>1){
        try{ tests=std::stoi(argv[1]); }catch(...){}
    }
    if(tests<=0){
        for(int i=1;i<10000;++i){
            std::string c="data/client_metrics_t"+std::to_string(i)+".csv";
            if(std::filesystem::exists(c)) tests=i;
            else break;
        }
    }
    if(tests<=0){
        std::cerr<<"No test files found."<<std::endl;
        return 1;
    }
    std::ofstream summary("paired_summary.txt");
    if(!summary.is_open()){
        std::cerr<<"Failed open summary file"<<std::endl;
        return 1;
    }

    std::vector<int64_t> allPlain, allEnc, allDelta;
    int totalValid=0;
    for(int t=1;t<=tests;++t){
        std::string cPath="data/client_metrics_t"+std::to_string(t)+".csv";
        std::string sPath="data/server_metrics_t"+std::to_string(t)+".csv";
        auto cRows=loadClient(cPath);
        auto sRows=loadServer(sPath);
        std::vector<PairMetrics> pairs;
        buildPairs(cRows,sRows,pairs);
        detectOutliers(pairs);
        assembleReasons(pairs);

        // per-test output
        std::string vf="paired_filtered_t"+std::to_string(t)+".csv";
        std::string inf="paired_invalid_t"+std::to_string(t)+".csv";
        std::ofstream valid(vf), invalid(inf);
        if(valid.is_open()&&invalid.is_open()){
            valid<<"pair_id,plain_latency_us,enc_latency_us,latency_delta_us,plain_size,enc_plain_size,enc_encrypted_size,encrypt_ns,plain_send_ns,enc_send_ns\n";
            invalid<<"pair_id,plain_latency_us,enc_latency_us,latency_delta_us,invalid_flags,reasons\n";
            for(auto&r:pairs){
                if(r.invalidFlags==0){
                    valid<<r.pairId<<","<<r.plainLatencyUs<<","<<r.encLatencyUs<<","<<r.latencyDeltaUs<<","<<r.plainSize<<","<<r.encPlainSize<<","<<r.encEncryptedSize<<","<<r.encEncryptNs<<","<<r.plainSendNs<<","<<r.encSendNs<<"\n";
                    if(r.plainLatencyUs>0) allPlain.push_back(r.plainLatencyUs);
                    if(r.encLatencyUs>0) allEnc.push_back(r.encLatencyUs);
                    if(r.latencyDeltaUs) allDelta.push_back(r.latencyDeltaUs);
                    ++totalValid;
                } else {
                    invalid<<r.pairId<<","<<r.plainLatencyUs<<","<<r.encLatencyUs<<","<<r.latencyDeltaUs<<","<<r.invalidFlags<<","<<r.reasons<<"\n";
                }
            }
        }
        writeTestSummary(summary,t,pairs);
    }

    Stats sp=computeStats(allPlain), se=computeStats(allEnc), sd=computeStats(allDelta);
    summary<<"Overall across "<<tests<<" tests: valid_pairs="<<totalValid<<"\n";
    summary<<"  Plain latency us: min="<<sp.min<<" max="<<sp.max<<" mean="<<sp.mean<<" median="<<sp.median<<" stddev="<<sp.stddev<<"\n";
    summary<<"  Encrypted latency us: min="<<se.min<<" max="<<se.max<<" mean="<<se.mean<<" median="<<se.median<<" stddev="<<se.stddev<<"\n";
    summary<<"  Delta (enc-plain) us: min="<<sd.min<<" max="<<sd.max<<" mean="<<sd.mean<<" median="<<sd.median<<" stddev="<<sd.stddev<<"\n";
    summary<<"  Mean overhead (enc - plain): "<<(se.mean - sp.mean)<<" us\n";

    std::cout<<"Analysis complete for "<<tests<<" tests. See paired_summary.txt and per-test CSV outputs."<<std::endl;
    return 0;
}