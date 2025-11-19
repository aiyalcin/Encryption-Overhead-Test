#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cstdint>
#include <cmath>

// Client CSV: pair_id,variant(0 plain 1 encrypted),plain_size,encrypted_size,encrypt_ns,send_ns,send_ts_us
// Server CSV: pair_id,variant,plain_size,encrypted_size,recv_ts_us,payload_bytes

struct ClientRow {
    uint32_t pairId{}; uint8_t variant{}; uint32_t plainSize{}; uint32_t encryptedSize{}; uint64_t encryptNs{}; uint64_t sendNs{}; uint64_t sendTsUs{}; bool parsed{false};
};
struct ServerRow {
    uint32_t pairId{}; uint8_t variant{}; uint32_t plainSize{}; uint32_t encryptedSize{}; uint64_t recvTsUs{}; uint32_t payloadBytes{}; bool parsed{false};
};

struct PairMetrics {
    uint32_t pairId{};
    // Plain
    uint64_t plainSendTsUs{}; uint64_t plainRecvTsUs{}; int64_t plainLatencyUs{}; uint64_t plainSendNs{}; uint32_t plainSize{};
    // Encrypted
    uint64_t encSendTsUs{}; uint64_t encRecvTsUs{}; int64_t encLatencyUs{}; uint64_t encSendNs{}; uint32_t encPlainSize{}; uint32_t encEncryptedSize{}; uint64_t encEncryptNs{};
    // Flags
    uint32_t invalidFlags{}; std::string reasons;
    // Derived deltas
    int64_t latencyDeltaUs{}; // enc - plain
};

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

static std::vector<std::string> splitCSV(const std::string& line) {
    std::vector<std::string> parts; std::stringstream ss(line); std::string item; while (std::getline(ss,item,',')) parts.push_back(item); return parts; }
static bool toUInt32(const std::string&s,uint32_t&v){try{v=(uint32_t)std::stoul(s);return true;}catch(...){return false;}}
static bool toUInt64(const std::string&s,uint64_t&v){try{v=(uint64_t)std::stoull(s);return true;}catch(...){return false;}}
static bool toInt(const std::string&s,int&v){try{v=std::stoi(s);return true;}catch(...){return false;}}

std::vector<ClientRow> loadClient(const std::string& path){std::ifstream in(path);std::vector<ClientRow> rows; if(!in.is_open()){std::cerr<<"Failed open client: "<<path<<"\n";return rows;} std::string line; bool header=true; while(std::getline(in,line)){ if(line.empty())continue; if(header){header=false;continue;} auto c=splitCSV(line); if(c.size()!=7)continue; ClientRow r; int var; if(!toUInt32(c[0],r.pairId))continue; if(!toInt(c[1],var))continue; r.variant=(uint8_t)var; if(!toUInt32(c[2],r.plainSize))continue; if(!toUInt32(c[3],r.encryptedSize))continue; if(!toUInt64(c[4],r.encryptNs))continue; if(!toUInt64(c[5],r.sendNs))continue; if(!toUInt64(c[6],r.sendTsUs))continue; r.parsed=true; rows.push_back(r);} return rows; }
std::vector<ServerRow> loadServer(const std::string& path){std::ifstream in(path);std::vector<ServerRow> rows; if(!in.is_open()){std::cerr<<"Failed open server: "<<path<<"\n";return rows;} std::string line; bool header=true; while(std::getline(in,line)){ if(line.empty())continue; if(header){header=false;continue;} auto c=splitCSV(line); if(c.size()!=6)continue; ServerRow r; int var; if(!toUInt32(c[0],r.pairId))continue; if(!toInt(c[1],var))continue; r.variant=(uint8_t)var; if(!toUInt32(c[2],r.plainSize))continue; if(!toUInt32(c[3],r.encryptedSize))continue; if(!toUInt64(c[4],r.recvTsUs))continue; if(!toUInt32(c[5],r.payloadBytes))continue; r.parsed=true; rows.push_back(r);} return rows; }

void buildPairs(const std::vector<ClientRow>& cRows, const std::vector<ServerRow>& sRows, std::vector<PairMetrics>& out){
    // Organize by pairId & variant
    std::unordered_map<uint64_t,ClientRow> cPlain,cEnc; std::unordered_map<uint64_t,ServerRow> sPlain,sEnc;
    for(auto const& c: cRows){ if(!c.parsed) continue; if(c.variant==0) cPlain[c.pairId]=c; else if(c.variant==1) cEnc[c.pairId]=c; }
    for(auto const& s: sRows){ if(!s.parsed) continue; if(s.variant==0) sPlain[s.pairId]=s; else if(s.variant==1) sEnc[s.pairId]=s; }
    // build union of pairIds
    std::unordered_map<uint64_t,bool> ids; for(auto& kv:cPlain) ids[kv.first]=true; for(auto& kv:cEnc) ids[kv.first]=true; for(auto& kv:sPlain) ids[kv.first]=true; for(auto& kv:sEnc) ids[kv.first]=true;
    out.reserve(ids.size());
    for(auto& kv: ids){ uint64_t id=kv.first; PairMetrics pm{}; pm.pairId=(uint32_t)id;
        bool hcP = cPlain.count(id); bool hcE = cEnc.count(id); bool hsP = sPlain.count(id); bool hsE = sEnc.count(id);
        if(hcP){ auto &c=cPlain[id]; pm.plainSendTsUs=c.sendTsUs; pm.plainSendNs=c.sendNs; pm.plainSize=c.plainSize; }
        else pm.invalidFlags |= MISSING_PLAIN_SEND;
        if(hcE){ auto &c=cEnc[id]; pm.encSendTsUs=c.sendTsUs; pm.encSendNs=c.sendNs; pm.encPlainSize=c.plainSize; pm.encEncryptedSize=c.encryptedSize; pm.encEncryptNs=c.encryptNs; }
        else pm.invalidFlags |= MISSING_ENC_SEND;
        if(hsP){ auto &s=sPlain[id]; pm.plainRecvTsUs=s.recvTsUs; }
        else pm.invalidFlags |= MISSING_PLAIN_RECV;
        if(hsE){ auto &s=sEnc[id]; pm.encRecvTsUs=s.recvTsUs; }
        else pm.invalidFlags |= MISSING_ENC_RECV;
        if(hcP && hsP){ pm.plainLatencyUs = (int64_t)pm.plainRecvTsUs - (int64_t)pm.plainSendTsUs; if(pm.plainLatencyUs < 0) pm.invalidFlags |= NEGATIVE_LAT_PLAIN; }
        if(hcE && hsE){ pm.encLatencyUs = (int64_t)pm.encRecvTsUs - (int64_t)pm.encSendTsUs; if(pm.encLatencyUs < 0) pm.invalidFlags |= NEGATIVE_LAT_ENC; }
        if(hcP && hsP){ if(pm.plainSize==0) pm.invalidFlags |= SIZE_MISMATCH_PLAIN; }
        if(hcE && hsE){ if(pm.encEncryptedSize==0 || pm.encPlainSize==0) pm.invalidFlags |= ENCRYPT_SIZE_INVALID; else if(pm.encEncryptedSize < pm.encPlainSize) pm.invalidFlags |= SIZE_MISMATCH_ENC; if(pm.encEncryptNs==0) pm.invalidFlags |= ZERO_ENCRYPT_TIME; }
        if(hcP && hcE){ pm.latencyDeltaUs = pm.encLatencyUs - pm.plainLatencyUs; }
        out.push_back(pm); }
}

static void detectOutliers(std::vector<PairMetrics>& rows){
    std::vector<int64_t> plainL, encL, deltas; plainL.reserve(rows.size()); encL.reserve(rows.size()); deltas.reserve(rows.size());
    for(auto &r: rows){ if(!(r.invalidFlags & (MISSING_PLAIN_SEND|MISSING_PLAIN_RECV|NEGATIVE_LAT_PLAIN)) && r.plainLatencyUs>0) plainL.push_back(r.plainLatencyUs); if(!(r.invalidFlags & (MISSING_ENC_SEND|MISSING_ENC_RECV|NEGATIVE_LAT_ENC)) && r.encLatencyUs>0) encL.push_back(r.encLatencyUs); if(r.invalidFlags==0 && r.plainLatencyUs>0 && r.encLatencyUs>0) deltas.push_back(r.latencyDeltaUs); }
    auto mark = [](std::vector<PairMetrics>& rows, const std::vector<int64_t>& values, uint32_t flag, auto accessor){ if(values.size()<8) return; std::vector<int64_t> tmp=values; std::nth_element(tmp.begin(), tmp.begin()+tmp.size()/2, tmp.end()); double med=(double)tmp[tmp.size()/2]; std::vector<double> dev; dev.reserve(values.size()); for(auto v: values) dev.push_back(std::abs(v-med)); std::nth_element(dev.begin(), dev.begin()+dev.size()/2, dev.end()); double mad=dev[dev.size()/2]; if(mad<1) mad=1; double thr=6.0*mad; for(auto &r: rows){ double val=(double)accessor(r); if(val>0){ double diff=std::abs(val-med); if(diff>thr) r.invalidFlags |= flag; } } };
    mark(rows, plainL, OUTLIER_LATENCY_PLAIN, [](const PairMetrics&r){return r.plainLatencyUs;});
    mark(rows, encL, OUTLIER_LATENCY_ENC, [](const PairMetrics&r){return r.encLatencyUs;});
    mark(rows, deltas, OUTLIER_DELTA, [](const PairMetrics&r){return r.latencyDeltaUs;});
}

static void assembleReasons(std::vector<PairMetrics>& rows){ for(auto &r: rows){ std::vector<std::string> rs; if(r.invalidFlags & MISSING_PLAIN_SEND) rs.push_back("missing_plain_send"); if(r.invalidFlags & MISSING_ENC_SEND) rs.push_back("missing_enc_send"); if(r.invalidFlags & MISSING_PLAIN_RECV) rs.push_back("missing_plain_recv"); if(r.invalidFlags & MISSING_ENC_RECV) rs.push_back("missing_enc_recv"); if(r.invalidFlags & SIZE_MISMATCH_PLAIN) rs.push_back("size_mismatch_plain"); if(r.invalidFlags & SIZE_MISMATCH_ENC) rs.push_back("size_mismatch_enc"); if(r.invalidFlags & ENCRYPT_SIZE_INVALID) rs.push_back("encrypt_size_invalid"); if(r.invalidFlags & NEGATIVE_LAT_PLAIN) rs.push_back("negative_latency_plain"); if(r.invalidFlags & NEGATIVE_LAT_ENC) rs.push_back("negative_latency_enc"); if(r.invalidFlags & ZERO_ENCRYPT_TIME) rs.push_back("zero_encrypt_time"); if(r.invalidFlags & OUTLIER_LATENCY_PLAIN) rs.push_back("outlier_latency_plain"); if(r.invalidFlags & OUTLIER_LATENCY_ENC) rs.push_back("outlier_latency_enc"); if(r.invalidFlags & OUTLIER_DELTA) rs.push_back("outlier_delta"); r.reasons.clear(); for(size_t i=0;i<rs.size();++i){ if(i) r.reasons+=';'; r.reasons+=rs[i]; } } }

struct Stats { double count{}; double min{}; double max{}; double mean{}; double median{}; double stddev{}; };
static Stats computeStats(const std::vector<int64_t>& v){ Stats s; if(v.empty()) return s; s.count=(double)v.size(); s.min=*std::min_element(v.begin(),v.end()); s.max=*std::max_element(v.begin(),v.end()); double sum=0; for(auto x:v) sum+=x; s.mean=sum/s.count; std::vector<int64_t> tmp=v; std::nth_element(tmp.begin(), tmp.begin()+tmp.size()/2, tmp.end()); s.median=(double)tmp[tmp.size()/2]; double acc=0; for(auto x:v){ double d=x - s.mean; acc+=d*d;} s.stddev=std::sqrt(acc/s.count); return s; }

static void writeOutputs(const std::vector<PairMetrics>& rows){ std::ofstream valid("paired_filtered.csv"), invalid("paired_invalid.csv"), summary("paired_summary.txt"); if(!valid.is_open()||!invalid.is_open()){ std::cerr<<"Failed open output files"<<std::endl; return;} valid<<"pair_id,plain_latency_us,enc_latency_us,latency_delta_us,plain_size,enc_plain_size,enc_encrypted_size,encrypt_ns,plain_send_ns,enc_send_ns\n"; invalid<<"pair_id,plain_latency_us,enc_latency_us,latency_delta_us,invalid_flags,reasons\n"; std::vector<int64_t> plainL, encL, deltaL; for(auto &r: rows){ if(r.invalidFlags==0){ valid<<r.pairId<<","<<r.plainLatencyUs<<","<<r.encLatencyUs<<","<<r.latencyDeltaUs<<","<<r.plainSize<<","<<r.encPlainSize<<","<<r.encEncryptedSize<<","<<r.encEncryptNs<<","<<r.plainSendNs<<","<<r.encSendNs<<"\n"; if(r.plainLatencyUs>0) plainL.push_back(r.plainLatencyUs); if(r.encLatencyUs>0) encL.push_back(r.encLatencyUs); if(r.latencyDeltaUs) deltaL.push_back(r.latencyDeltaUs);} else { invalid<<r.pairId<<","<<r.plainLatencyUs<<","<<r.encLatencyUs<<","<<r.latencyDeltaUs<<","<<r.invalidFlags<<","<<r.reasons<<"\n"; } } Stats sp=computeStats(plainL), se=computeStats(encL), sd=computeStats(deltaL); if(summary.is_open()){ summary<<"Valid pairs: "<<(int)sp.count<<"\n"; summary<<"Plain latency us: min="<<sp.min<<" max="<<sp.max<<" mean="<<sp.mean<<" median="<<sp.median<<" stddev="<<sp.stddev<<"\n"; summary<<"Encrypted latency us: min="<<se.min<<" max="<<se.max<<" mean="<<se.mean<<" median="<<se.median<<" stddev="<<se.stddev<<"\n"; summary<<"Delta (enc-plain) us: min="<<sd.min<<" max="<<sd.max<<" mean="<<sd.mean<<" median="<<sd.median<<" stddev="<<sd.stddev<<"\n"; summary<<"Mean overhead (enc - plain): "<<se.mean - sp.mean<<" us\n"; }
}

int main(int argc,char* argv[]){ std::string clientPath="client_metrics.csv", serverPath="server_metrics.csv"; if(argc>1) clientPath=argv[1]; if(argc>2) serverPath=argv[2]; std::cout<<"Loading client from "<<clientPath<<"\n"; auto cRows=loadClient(clientPath); std::cout<<"Client rows: "<<cRows.size()<<"\n"; std::cout<<"Loading server from "<<serverPath<<"\n"; auto sRows=loadServer(serverPath); std::cout<<"Server rows: "<<sRows.size()<<"\n"; std::vector<PairMetrics> pairs; buildPairs(cRows,sRows,pairs); detectOutliers(pairs); assembleReasons(pairs); writeOutputs(pairs); std::cout<<"Analysis complete. See paired_filtered.csv, paired_invalid.csv, paired_summary.txt\n"; return 0; }