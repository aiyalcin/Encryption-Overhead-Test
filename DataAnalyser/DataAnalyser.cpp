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

// Updated analyser to support new variants: HASHED (4) and ENC_HASHED (5)
// Client CSV columns now: pair_id, variant, plain_size, transformed_size, encrypt_ns, hash_ns, send_ns, send_ts_us
// Server CSV columns now: pair_id, variant, plain_size, transformed_size, recv_ts_us, payload_bytes

// -----------------------------------------------------------------------------
// CSV column definitions
// Client CSV: pair_id, variant, plain_size, transformed_size,
//             encrypt_ns, hash_ns, send_ns, send_ts_us
// Server CSV: pair_id, variant, plain_size, transformed_size, recv_ts_us, payload_bytes
// ---------------------------------------------------------------------------->

// Represents a parsed row from the client metrics CSV
struct ClientRow {
    uint32_t pairId{};
    uint8_t  variant{};            // 0 = plain, 1 = encrypted, 4 = hashed, 5 = encrypted + hashed
    uint32_t plainSize{};
    uint32_t transformedSize{};
    uint64_t encryptNs{};          // encryption duration in ns
    uint64_t hashNs{};             // hashing duration in ns (for hashed/encrypted+hashed)
    uint64_t sendNs{};             // time spent preparing/sending in ns (client side)
    uint64_t sendTsUs{};           // send timestamp (microseconds epoch or monotonic)
    bool     parsed{false};
};

// Represents a parsed row from the server metrics CSV
struct ServerRow {
    uint32_t pairId{};
    uint8_t  variant{};            // 0 = plain, 1 = encrypted, 4 = hashed, 5 = encrypted + hashed
    uint32_t plainSize{};
    uint32_t transformedSize{};
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

    // Encrypted / Hashed message metrics
    uint64_t encSendTsUs{};
    uint64_t encRecvTsUs{};
    int64_t  encLatencyUs{};       // recv - send (encrypted/hashed variant)
    uint64_t encSendNs{};
    uint32_t encPlainSize{};       // original plain size before encryption
    uint32_t encTransformedSize{}; // size after encryption or hashing
    uint64_t encEncryptNs{};       // encryption duration
    uint64_t encHashNs{};          // hashing duration (if applicable)
    uint8_t  encVariant{};         // variant type (1=encrypted, 4=hashed, 5=enc+hashed)

    // Validation / flagging
    uint32_t    invalidFlags{};    // bit mask of InvalidBits
    std::string reasons;           // human-readable concatenated reasons

    // Derived delta (transformed - plain)
    int64_t latencyDeltaUs{};
};

// Bit mask flags identifying invalid or outlier conditions
enum InvalidBits : uint32_t {
    MISSING_PLAIN_SEND      = 1u << 0,
    MISSING_TRANS_SEND        = 1u << 1,
    MISSING_PLAIN_RECV      = 1u << 2,
    MISSING_TRANS_RECV        = 1u << 3,
    SIZE_MISMATCH_PLAIN     = 1u << 4,
    SIZE_MISMATCH_TRANS       = 1u << 5,
    NEGATIVE_LAT_PLAIN      = 1u << 6,
    NEGATIVE_LAT_TRANS        = 1u << 7,
    ZERO_ENCRYPT_TIME       = 1u << 8,
    ZERO_HASH_TIME          = 1u << 9,
    OUTLIER_LATENCY_PLAIN   = 1u << 10,
    OUTLIER_LATENCY_TRANS     = 1u << 11,
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
    ClientRow r; if (cols.size() != 8) return r;
    int var{};
    if (!toUInt32(cols[0], r.pairId)) return r;
    if (!toInt(cols[1], var)) return r; r.variant = static_cast<uint8_t>(var);
    if (!toUInt32(cols[2], r.plainSize)) return r;
    if (!toUInt32(cols[3], r.transformedSize)) return r;
    if (!toUInt64(cols[4], r.encryptNs)) return r;
    if (!toUInt64(cols[5], r.hashNs)) return r;
    if (!toUInt64(cols[6], r.sendNs)) return r;
    if (!toUInt64(cols[7], r.sendTsUs)) return r;
    r.parsed = true; return r;
}

static ServerRow parseServerRow(const std::vector<std::string>& cols) {
    ServerRow r; if (cols.size() != 6) return r;
    int var{};
    if (!toUInt32(cols[0], r.pairId)) return r;
    if (!toInt(cols[1], var)) return r; r.variant = static_cast<uint8_t>(var);
    if (!toUInt32(cols[2], r.plainSize)) return r;
    if (!toUInt32(cols[3], r.transformedSize)) return r;
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
    std::unordered_map<uint64_t, ClientRow> cPlain, cTrans;
    std::unordered_map<uint64_t, ServerRow> sPlain, sTrans;

    for (const auto& c : cRows) {
        if (!c.parsed) continue;
        if (c.variant == 0) cPlain[c.pairId] = c;
        else if (c.variant == 1 || c.variant == 4 || c.variant == 5) cTrans[c.pairId] = c;
    }
    for (const auto& s : sRows) {
        if (!s.parsed) continue;
        if (s.variant == 0) sPlain[s.pairId] = s;
        else if (s.variant == 1 || s.variant == 4 || s.variant == 5) sTrans[s.pairId] = s;
    }

    std::unordered_map<uint64_t, bool> ids;
    for (auto& keyValue : cPlain) ids[keyValue.first] = true;
    for (auto& keyValue : cTrans) ids[keyValue.first] = true;
    for (auto& keyValue : sPlain) ids[keyValue.first] = true;
    for (auto& keyValue : sTrans) ids[keyValue.first] = true;

    out.reserve(ids.size());

    for (auto& keyValue : ids) {
        uint64_t id = keyValue.first; PairMetrics pairMetrics{}; pairMetrics.pairId = static_cast<uint32_t>(id);
        bool hcP = cPlain.count(id) != 0;
        bool hcT = cTrans.count(id)   != 0;
        bool hsP = sPlain.count(id) != 0;
        bool hsT = sTrans.count(id)   != 0;

        // Plain send data
        if (hcP) {
            const auto& c = cPlain[id];
            pairMetrics.plainSendTsUs = c.sendTsUs;
            pairMetrics.plainSendNs   = c.sendNs;
            pairMetrics.plainSize     = c.plainSize;
        } else {
            pairMetrics.invalidFlags |= MISSING_PLAIN_SEND;
        }

        // Encrypted / Hashed send data
        if (hcT) {
            const auto& c = cTrans[id];
            pairMetrics.encSendTsUs      = c.sendTsUs;
            pairMetrics.encSendNs        = c.sendNs;
            pairMetrics.encPlainSize     = c.plainSize;
            pairMetrics.encTransformedSize = c.transformedSize;
            pairMetrics.encEncryptNs     = c.encryptNs;
            pairMetrics.encHashNs        = c.hashNs;
            pairMetrics.encVariant       = c.variant;
        } else {
            pairMetrics.invalidFlags |= MISSING_TRANS_SEND;
        }

        // Receive timestamps
        if (hsP) {
            pairMetrics.plainRecvTsUs = sPlain[id].recvTsUs;
        } else {
            pairMetrics.invalidFlags |= MISSING_PLAIN_RECV;
        }
        if (hsT) {
            pairMetrics.encRecvTsUs = sTrans[id].recvTsUs;
        } else {
            pairMetrics.invalidFlags |= MISSING_TRANS_RECV;
        }

        // Latencies and validations
        if (hcP && hsP) {
            pairMetrics.plainLatencyUs = static_cast<int64_t>(pairMetrics.plainRecvTsUs) - static_cast<int64_t>(pairMetrics.plainSendTsUs);
            if (pairMetrics.plainLatencyUs < 0) pairMetrics.invalidFlags |= NEGATIVE_LAT_PLAIN;
            if (pairMetrics.plainSize == 0)     pairMetrics.invalidFlags |= SIZE_MISMATCH_PLAIN;
        }
        if (hcT && hsT) {
            pairMetrics.encLatencyUs = static_cast<int64_t>(pairMetrics.encRecvTsUs) - static_cast<int64_t>(pairMetrics.encSendTsUs);
            if (pairMetrics.encLatencyUs < 0) pairMetrics.invalidFlags |= NEGATIVE_LAT_TRANS;
            if (pairMetrics.encTransformedSize == 0 && (pairMetrics.encVariant == 1 || pairMetrics.encVariant == 5)) {
                pairMetrics.invalidFlags |= SIZE_MISMATCH_TRANS;
            }
            if (pairMetrics.encVariant == 1 || pairMetrics.encVariant == 5) {
                if (pairMetrics.encEncryptNs == 0) pairMetrics.invalidFlags |= ZERO_ENCRYPT_TIME;
            }
            if (pairMetrics.encVariant == 4 || pairMetrics.encVariant == 5) {
                if (pairMetrics.encHashNs == 0) pairMetrics.invalidFlags |= ZERO_HASH_TIME;
            }
        }
        if (hcP && hcT) {
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
    std::vector<int64_t> plainL, transL, deltas;
    plainL.reserve(rows.size()); transL.reserve(rows.size()); deltas.reserve(rows.size());
    for (auto& r : rows) {
        bool plainValid = !(r.invalidFlags & (MISSING_PLAIN_SEND | MISSING_PLAIN_RECV | NEGATIVE_LAT_PLAIN)) && r.plainLatencyUs > 0;
        bool transValid   = !(r.invalidFlags & (MISSING_TRANS_SEND   | MISSING_TRANS_RECV   | NEGATIVE_LAT_TRANS))   && r.encLatencyUs   > 0;
        if (plainValid) plainL.push_back(r.plainLatencyUs);
        if (transValid)   transL.push_back(r.encLatencyUs);
        if (r.invalidFlags == 0 && r.plainLatencyUs > 0 && r.encLatencyUs > 0) deltas.push_back(r.latencyDeltaUs);
    }
    markOutliers(rows, plainL, OUTLIER_LATENCY_PLAIN, [](const PairMetrics& r){ return r.plainLatencyUs; });
    markOutliers(rows, transL,   OUTLIER_LATENCY_TRANS,   [](const PairMetrics& r){ return r.encLatencyUs;   });
    markOutliers(rows, deltas, OUTLIER_DELTA,         [](const PairMetrics& r){ return r.latencyDeltaUs; });
}

// -----------------------------------------------------------------------------
// Reason assembly
// ---------------------------------------------------------------------------->
static void assembleReasons(std::vector<PairMetrics>& rows) {
    struct Map { uint32_t bit; const char* text; };
    static const Map map[] = {
        { MISSING_PLAIN_SEND,    "missing_plain_send" },
        { MISSING_TRANS_SEND,      "missing_trans_send" },
        { MISSING_PLAIN_RECV,    "missing_plain_recv" },
        { MISSING_TRANS_RECV,      "missing_trans_recv" },
        { SIZE_MISMATCH_PLAIN,   "size_mismatch_plain" },
        { SIZE_MISMATCH_TRANS,     "size_mismatch_trans" },
        { NEGATIVE_LAT_PLAIN,    "negative_latency_plain" },
        { NEGATIVE_LAT_TRANS,      "negative_latency_trans" },
        { ZERO_ENCRYPT_TIME,     "zero_encrypt_time" },
        { ZERO_HASH_TIME,          "zero_hash_time" },
        { OUTLIER_LATENCY_PLAIN, "outlier_latency_plain" },
        { OUTLIER_LATENCY_TRANS,   "outlier_latency_trans" },
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

    valid   << "pair_id,plain_latency_us,enc_latency_us,latency_delta_us,plain_size,enc_plain_size,enc_transformed_size,encrypt_ns,hash_ns,plain_send_ns,enc_send_ns,variant\n";
    invalid << "pair_id,plain_latency_us,enc_latency_us,latency_delta_us,invalid_flags,reasons,variant\n";

    std::vector<int64_t> plainL, encL, deltaL;
    for (const auto& r : rows) {
        if (r.invalidFlags == 0) {
            valid << r.pairId << ','
                  << r.plainLatencyUs << ','
                  << r.encLatencyUs << ','
                  << r.latencyDeltaUs << ','
                  << r.plainSize << ','
                  << r.encPlainSize << ','
                  << r.encTransformedSize << ','
                  << r.encEncryptNs << ','
                  << r.encHashNs << ','
                  << r.plainSendNs << ','
                  << r.encSendNs << ','
                  << static_cast<int>(r.encVariant) << '\n';
            if (r.plainLatencyUs > 0) plainL.push_back(r.plainLatencyUs);
            if (r.encLatencyUs > 0)   encL.push_back(r.encLatencyUs);
            if (r.latencyDeltaUs)     deltaL.push_back(r.latencyDeltaUs);
        } else {
            invalid << r.pairId << ','
                    << r.plainLatencyUs << ','
                    << r.encLatencyUs << ','
                    << r.latencyDeltaUs << ','
                    << r.invalidFlags << ','
                    << r.reasons << ','
                    << static_cast<int>(r.encVariant) << '\n';
        }
    }

    Stats sp = computeStats(plainL), st = computeStats(encL), sd = computeStats(deltaL);
    if (summary.is_open()) {
        summary << "Valid pairs: " << static_cast<int>(sp.count) << '\n';
        summary << "Plain latency us: min=" << sp.min << " max=" << sp.max << " mean=" << sp.mean << " median=" << sp.median << " stddev=" << sp.stddev << '\n';
        summary << "Transformed latency us: min=" << st.min << " max=" << st.max << " mean=" << st.mean << " median=" << st.median << " stddev=" << st.stddev << '\n';
        summary << "Delta (trans-plain) us: min=" << sd.min << " max=" << sd.max << " mean=" << sd.mean << " median=" << sd.median << " stddev=" << sd.stddev << '\n';
        summary << "Mean overhead (trans - plain): " << (st.mean - sp.mean) << " us\n";
    }
}

static void writeTestSummary(std::ofstream& summary,int t,const std::vector<PairMetrics>& rows){
    std::vector<int64_t> plainL, transL, deltaL;
    int encCnt=0, hashCnt=0, encHashCnt=0;
    uint64_t sumEncNs=0, sumHashNs=0;
    for(auto&r:rows){
        if(r.invalidFlags==0){
            if(r.plainLatencyUs>0) plainL.push_back(r.plainLatencyUs);
            if(r.encLatencyUs>0) transL.push_back(r.encLatencyUs);
            if(r.latencyDeltaUs) deltaL.push_back(r.latencyDeltaUs);
            if(r.encVariant==1){ ++encCnt; sumEncNs += r.encEncryptNs; }
            else if(r.encVariant==4){ ++hashCnt; sumHashNs += r.encHashNs; }
            else if(r.encVariant==5){ ++encHashCnt; sumEncNs += r.encEncryptNs; sumHashNs += r.encHashNs; }
        }
    }
    Stats sp=computeStats(plainL), st=computeStats(transL), sd=computeStats(deltaL);
    summary<<"Test "<<t<<": valid_pairs="<<(int)sp.count<<"\n";
    summary<<"  Plain latency us: min="<<sp.min<<" max="<<sp.max<<" mean="<<sp.mean<<" median="<<sp.median<<" stddev="<<sp.stddev<<"\n";
    summary<<"  Transformed latency us: min="<<st.min<<" max="<<st.max<<" mean="<<st.mean<<" median="<<st.median<<" stddev="<<st.stddev<<"\n";
    summary<<"  Delta (trans-plain) us: min="<<sd.min<<" max="<<sd.max<<" mean="<<sd.mean<<" median="<<sd.median<<" stddev="<<sd.stddev<<"\n";
    if(encCnt) summary<<"  Mean encrypt ns (per encrypted only): "<<(double)sumEncNs/encCnt<<"\n";
    if(hashCnt) summary<<"  Mean hash ns (per hashed only): "<<(double)sumHashNs/hashCnt<<"\n";
    if(encHashCnt) summary<<"  Mean encrypt ns (enc+hash): "<<(double)sumEncNs/encHashCnt<<"  Mean hash ns (enc+hash): "<<(double)sumHashNs/encHashCnt<<"\n";
    summary<<"  Mean overhead (trans - plain): "<<(st.mean - sp.mean)<<" us\n\n";
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

    std::vector<int64_t> allPlain, allTrans, allDelta;
    int totalValid=0;
    uint64_t totalEncNs=0,totalHashNs=0;
    int totalEncCnt=0,totalHashCnt=0,totalEncHashCnt=0; 
    for(int t=1; t<=tests; ++t){
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
        if(valid.is_open() && invalid.is_open()){
            valid<<"pair_id,plain_latency_us,trans_latency_us,latency_delta_us,plain_size,trans_plain_size,transformed_size,encrypt_ns,hash_ns,plain_send_ns,trans_send_ns,variant\n";
            invalid<<"pair_id,plain_latency_us,trans_latency_us,latency_delta_us,invalid_flags,reasons,variant\n";
            for(auto&r:pairs){
                if(r.invalidFlags==0){
                    valid<<r.pairId<<","<<r.plainLatencyUs<<","<<r.encLatencyUs<<","<<r.latencyDeltaUs<<","<<r.plainSize<<","<<r.encPlainSize<<","<<r.encTransformedSize<<","<<r.encEncryptNs<<","<<r.encHashNs<<","<<r.plainSendNs<<","<<r.encSendNs<<","<<(int)r.encVariant<<"\n";
                    if(r.plainLatencyUs>0) allPlain.push_back(r.plainLatencyUs);
                    if(r.encLatencyUs>0) allTrans.push_back(r.encLatencyUs);
                    if(r.latencyDeltaUs) allDelta.push_back(r.latencyDeltaUs);
                    if(r.encVariant==1){ totalEncNs+=r.encEncryptNs; ++totalEncCnt; } 
                    else if(r.encVariant==4){ totalHashNs+=r.encHashNs; ++totalHashCnt; } 
                    else if(r.encVariant==5){ totalEncNs+=r.encEncryptNs; totalHashNs+=r.encHashNs; ++totalEncHashCnt; } 
                    ++totalValid;
                } else {
                    invalid<<r.pairId<<","<<r.plainLatencyUs<<","<<r.encLatencyUs<<","<<r.latencyDeltaUs<<","<<r.invalidFlags<<","<<r.reasons<<","<<(int)r.encVariant<<"\n";
                }
            }
        }
        writeTestSummary(summary,t,pairs);
    }

    Stats sp=computeStats(allPlain), st=computeStats(allTrans), sd=computeStats(allDelta);
    summary<<"Overall across "<<tests<<" tests: valid_pairs="<<totalValid<<"\n";
    summary<<"  Plain latency us: min="<<sp.min<<" max="<<sp.max<<" mean="<<sp.mean<<" median="<<sp.median<<" stddev="<<sp.stddev<<"\n";
    summary<<"  Transformed latency us: min="<<st.min<<" max="<<st.max<<" mean="<<st.mean<<" median="<<st.median<<" stddev="<<st.stddev<<"\n";
    summary<<"  Delta (trans-plain) us: min="<<sd.min<<" max="<<sd.max<<" mean="<<sd.mean<<" median="<<sd.median<<" stddev="<<sd.stddev<<"\n";
    if(totalEncCnt) summary<<"  Mean encrypt ns (all encrypted-only): "<<(double)totalEncNs/totalEncCnt<<"\n";
    if(totalHashCnt) summary<<"  Mean hash ns (all hashed-only): "<<(double)totalHashNs/totalHashCnt<<"\n";
    if(totalEncHashCnt) summary<<"  Mean encrypt ns (enc+hash): "<<(double)totalEncNs/totalEncHashCnt<<"  Mean hash ns (enc+hash): "<<(double)totalHashNs/totalEncHashCnt<<"\n";
    summary<<"  Mean overhead (trans - plain): "<<(st.mean - sp.mean)<<" us\n";

    std::cout<<"Analysis complete for "<<tests<<" tests. See paired_summary.txt."<<std::endl;
    return 0;
}