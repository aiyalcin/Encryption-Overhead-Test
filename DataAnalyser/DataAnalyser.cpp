#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

// -----------------------------------------------------------------------------
// Simplified latency analyser for transformed vs plain packets.
// Input CSVs (per test index T):
//   data/client_metrics_tT.csv : pair_id,variant,send_ts_us
//   data/server_metrics_tT.csv : pair_id,variant,recv_ts_us
// Variants: 0=PLAIN, 1=ENCRYPTED, 4=HASHED, 5=ENC_HASHED
// Output files per test:
//   paired_filtered_tT.csv : pair_id,plain_latency_us,trans_latency_us,latency_delta_us,variant
//   paired_invalid_tT.csv  : pair_id,reason
// Summary: paired_summary.txt  (mean latencies and delta per test)
// ----------------------------------------------------------------------------

// Variant constants
static constexpr uint8_t VAR_PLAIN     = 0;
static constexpr uint8_t VAR_ENCRYPTED = 1;
static constexpr uint8_t VAR_HASHED    = 4;
static constexpr uint8_t VAR_ENC_HASH  = 5;

static inline bool isTransformed(uint8_t variant) {
    return variant == VAR_ENCRYPTED || variant == VAR_HASHED || variant == VAR_ENC_HASH;
}

// Single CSV row (client or server)
struct Row {
    uint32_t id{};      // pair_id
    uint8_t  variant{}; // variant
    uint64_t timestampUs{};      // send or recv timestamp (us)
    bool     ok{false}; // parsed status
};

// Valid paired metrics
struct PairMetrics {
    uint32_t id;
    uint64_t plainLatencyUs;
    uint64_t transformedLatencyUs;
    int64_t  deltaLatencyUs;       // transformed - plain
    uint8_t  transformedVariant;   // transformed variant
};

// Invalid pair entry
struct InvalidPair {
    uint32_t id;
    std::string reason;
};

// Parsed input collections for a test
struct TestData {
    std::unordered_map<uint32_t, Row> clientPlainRows;
    std::unordered_map<uint32_t, Row> clientTransformedRows;
    std::unordered_map<uint32_t, Row> serverPlainRows;
    std::unordered_map<uint32_t, Row> serverTransformedRows;
};

// -----------------------------------------------------------------------------
// Parsing helpers
// -----------------------------------------------------------------------------
static bool parseUInt32(const std::string& s, uint32_t& v) { try { v = (uint32_t)std::stoul(s); return true; } catch (...) { return false; } }
static bool parseUInt64(const std::string& s, uint64_t& v) { try { v = (uint64_t)std::stoull(s); return true; } catch (...) { return false; } }
static bool parseInt(const std::string& s, int& v)       { try { v = std::stoi(s); return true; } catch (...) { return false; } }

static Row parseLine(const std::string& line) {
    Row row; std::stringstream ss(line); std::string idStr, variantStr, tsStr;
    if (!std::getline(ss, idStr, ',')) return row;
    if (!std::getline(ss, variantStr, ',')) return row;
    if (!std::getline(ss, tsStr, ',')) return row;
    int variantInt = 0;
    if (!parseUInt32(idStr, row.id)) return row;
    if (!parseInt(variantStr, variantInt))     return row;
    if (!parseUInt64(tsStr, row.timestampUs)) return row;
    row.variant = (uint8_t)variantInt;
    row.ok = true;
    return row;
}

// Load client or server CSV into maps
static void loadCsv(const std::string& path,
                    std::unordered_map<uint32_t, Row>& plainOut,
                    std::unordered_map<uint32_t, Row>& transformedOut) {
    std::ifstream in(path);
    if (!in.is_open()) return; // silently ignore missing file here

    std::string line; bool header = true;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (header) { header = false; continue; }
        Row row = parseLine(line);
        if (!row.ok) continue;
        if (row.variant == VAR_PLAIN) plainOut[row.id] = row;
        else if (isTransformed(row.variant)) transformedOut[row.id] = row;
    }
}

// -----------------------------------------------------------------------------
// Core processing
// -----------------------------------------------------------------------------
static void buildTestData(int testIndex, TestData& data) {
    const std::string clientPath = "data/client_metrics_t" + std::to_string(testIndex) + ".csv";
    const std::string serverPath = "data/server_metrics_t" + std::to_string(testIndex) + ".csv";
    if (!std::filesystem::exists(clientPath) || !std::filesystem::exists(serverPath)) return;
    loadCsv(clientPath, data.clientPlainRows,  data.clientTransformedRows);
    loadCsv(serverPath, data.serverPlainRows, data.serverTransformedRows);
}

static void pairRows(const TestData& data,
                     std::vector<PairMetrics>& validPairs,
                     std::vector<InvalidPair>& invalidPairs) {
    // Iterate client plain rows as anchor
    for (const auto& clientPlainEntry : data.clientPlainRows) {
        uint32_t id = clientPlainEntry.first;
        auto clientPlainIt       = data.clientPlainRows.find(id);
        auto serverPlainIt       = data.serverPlainRows.find(id);
        auto clientTransformedIt = data.clientTransformedRows.find(id);
        auto serverTransformedIt = data.serverTransformedRows.find(id);

        bool missing = (clientPlainIt == data.clientPlainRows.end() ||
                        serverPlainIt == data.serverPlainRows.end() ||
                        clientTransformedIt == data.clientTransformedRows.end() ||
                        serverTransformedIt == data.serverTransformedRows.end());
        if (missing) {
            invalidPairs.push_back({ id, "missing_counterpart" });
            continue;
        }

        uint64_t plainLatencyUs = (serverPlainIt->second.timestampUs >= clientPlainIt->second.timestampUs)
                                ? (serverPlainIt->second.timestampUs - clientPlainIt->second.timestampUs) : 0;
        uint64_t transformedLatencyUs = (serverTransformedIt->second.timestampUs >= clientTransformedIt->second.timestampUs)
                                      ? (serverTransformedIt->second.timestampUs - clientTransformedIt->second.timestampUs) : 0;
        if (plainLatencyUs == 0 || transformedLatencyUs == 0) {
            invalidPairs.push_back({ id, "non_positive_latency" });
            continue;
        }
        int64_t deltaLatencyUs = (int64_t)transformedLatencyUs - (int64_t)plainLatencyUs;
        validPairs.push_back({ id, plainLatencyUs, transformedLatencyUs, deltaLatencyUs, clientTransformedIt->second.variant });
    }
}

static void writePerTestFiles(int testIndex,
                              const std::vector<PairMetrics>& validPairs,
                              const std::vector<InvalidPair>& invalidPairs) {
    // Valid pairs
    {
        std::ofstream out("paired_filtered_t" + std::to_string(testIndex) + ".csv");
        if (out.is_open()) {
            out << "pair_id,plain_latency_us,trans_latency_us,latency_delta_us,variant\n";
            for (const auto& pairMetrics : validPairs) {
                out << pairMetrics.id << ','
                    << pairMetrics.plainLatencyUs << ','
                    << pairMetrics.transformedLatencyUs << ','
                    << pairMetrics.deltaLatencyUs << ','
                    << (int)pairMetrics.transformedVariant << '\n';
            }
        }
    }
    // Invalid pairs
    {
        std::ofstream out("paired_invalid_t" + std::to_string(testIndex) + ".csv");
        if (out.is_open()) {
            out << "pair_id,reason\n";
            for (const auto& invalid : invalidPairs) {
                out << invalid.id << ',' << invalid.reason << '\n';
            }
        }
    }
}

static void writeSummaryLine(std::ofstream& summary,
                             int testIndex,
                             const std::vector<PairMetrics>& validPairs) {
    double sumPlainLatency = 0.0, sumTransformedLatency = 0.0;
    int sampleCount = 0;
    for (const auto& pairMetrics : validPairs) {
        sumPlainLatency       += (double)pairMetrics.plainLatencyUs;
        sumTransformedLatency += (double)pairMetrics.transformedLatencyUs;
        ++sampleCount;
    }
    double meanPlainLatency       = sampleCount ? (sumPlainLatency / sampleCount) : 0.0;
    double meanTransformedLatency = sampleCount ? (sumTransformedLatency / sampleCount) : 0.0;

    summary << "Test " << testIndex << ": valid_pairs=" << validPairs.size() << '\n'
            << "  Mean plain latency us=" << meanPlainLatency << '\n'
            << "  Mean transformed latency us=" << meanTransformedLatency << '\n'
            << "  Mean delta (trans - plain) us=" << (meanTransformedLatency - meanPlainLatency) << "\n\n";
}

// -----------------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    int testsToProcess = 0;
    if (argc > 1) { try { testsToProcess = std::stoi(argv[1]); } catch (...) {} }
    if (testsToProcess <= 0) {
        for (int i = 1; i < 10000; ++i) {
            if (std::filesystem::exists("data/client_metrics_t" + std::to_string(i) + ".csv")) testsToProcess = i; else break;
        }
    }
    if (testsToProcess <= 0) {
        std::cerr << "No test files found." << std::endl;
        return 1;
    }

    std::ofstream summary("paired_summary.txt");
    if (!summary.is_open()) {
        std::cerr << "Cannot open summary file" << std::endl;
        return 1;
    }

    for (int testIndex = 1; testIndex <= testsToProcess; ++testIndex) {
        TestData testData;
        buildTestData(testIndex, testData);

        std::vector<PairMetrics> validPairs;
        std::vector<InvalidPair> invalidPairs;
        validPairs.reserve(testData.clientPlainRows.size());
        invalidPairs.reserve(16);

        pairRows(testData, validPairs, invalidPairs);
        writePerTestFiles(testIndex, validPairs, invalidPairs);
        writeSummaryLine(summary, testIndex, validPairs);
    }

    std::cout << "Analysis complete." << std::endl;
    return 0;
}