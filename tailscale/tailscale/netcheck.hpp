#pragma once

// Windows compatibility
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7 or later
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <asio.hpp>
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <functional>
#include <set>

namespace netcheck {

using steady_clock = std::chrono::steady_clock;
using time_point = steady_clock::time_point;
using duration = steady_clock::duration;

// Forward declarations
struct DERPNode;
struct DERPRegion;
struct DERPMap;
class Client;

// OptBool represents a tri-state boolean (unset, true, false)
class OptBool {
public:
    OptBool() : state_(State::Unset) {}
    explicit OptBool(bool value) : state_(value ? State::True : State::False) {}
    
    void set(bool value) { state_ = value ? State::True : State::False; }
    bool has_value() const { return state_ != State::Unset; }
    bool value() const { return state_ == State::True; }
    bool equal_bool(bool b) const { return has_value() && value() == b; }
    
    std::string to_string() const {
        switch (state_) {
            case State::Unset: return "";
            case State::True: return "true";
            case State::False: return "false";
        }
        return "";
    }

private:
    enum class State { Unset, True, False };
    State state_;
};

// Report contains the result of a single netcheck
struct Report {
    time_point now;
    bool udp = false;
    bool ipv6 = false;
    bool ipv4 = false;
    bool ipv6_can_send = false;
    bool ipv4_can_send = false;
    bool os_has_ipv6 = false;
    bool icmpv4 = false;
    
    OptBool mapping_varies_by_dest_ip;
    OptBool upnp;
    OptBool pmp;
    OptBool pcp;
    OptBool captive_portal;
    
    int preferred_derp = 0;
    std::map<int, duration> region_latency;
    std::map<int, duration> region_v4_latency;
    std::map<int, duration> region_v6_latency;
    
    std::map<asio::ip::udp::endpoint, int> global_v4_counters;
    std::map<asio::ip::udp::endpoint, int> global_v6_counters;
    
    asio::ip::udp::endpoint global_v4;
    asio::ip::udp::endpoint global_v6;
    
    bool AnyPortMappingChecked() const {
        return upnp.has_value() || pmp.has_value() || pcp.has_value();
    }
    
    std::pair<std::vector<asio::ip::udp::endpoint>, 
              std::vector<asio::ip::udp::endpoint>> GetGlobalAddrs() const;
};

// DERP node configuration
struct DERPNode {
    std::string name;
    int region_id = 0;
    std::string host_name;
    std::string ipv4;
    std::string ipv6;
    int stun_port = -1;
    std::string stun_test_ip;
    bool stun_only = false;
    
    bool IsTestNode() const { return false; } // For testing purposes
};

// DERP region configuration
struct DERPRegion {
    int region_id = 0;
    std::string region_code;
    std::string region_name;  // Display name like "London", "New York City"
    bool avoid = false;
    bool no_measure_no_home = false;
    std::vector<std::shared_ptr<DERPNode>> nodes;
};

// DERP map containing all regions
struct DERPMap {
    std::map<int, std::shared_ptr<DERPRegion>> regions;
    
    std::vector<int> RegionIds() const {
        std::vector<int> ids;
        for (const auto& [id, _] : regions) {
            ids.push_back(id);
        }
        return ids;
    }
};

// Network interface state
struct InterfaceState {
    bool have_v4 = false;
    bool have_v6 = false;
};

// Probe protocol type
enum class ProbeProto {
    IPv4,
    IPv6,
    HTTPS
};

inline std::string to_string(ProbeProto proto) {
    switch (proto) {
        case ProbeProto::IPv4: return "v4";
        case ProbeProto::IPv6: return "v6";
        case ProbeProto::HTTPS: return "https";
    }
    return "?";
}

// Individual probe definition
struct Probe {
    duration delay;
    std::string node;
    ProbeProto proto;
    duration wait;
};

// Probe plan for a netcheck run
using ProbePlan = std::map<std::string, std::vector<Probe>>;

// Options for GetReport
struct GetReportOpts {
    std::function<time_point(int)> GetLastDerpActivity;
    bool only_tcp443 = false;
    bool only_stun = false;
};

// Constants
namespace constants {
    constexpr auto report_timeout = std::chrono::seconds(5);
    constexpr auto stun_probe_timeout = std::chrono::seconds(3);
    constexpr auto icmp_probe_timeout = std::chrono::seconds(1);
    constexpr auto https_probe_timeout = report_timeout;
    constexpr auto default_active_retransmit_time = std::chrono::milliseconds(200);
    constexpr auto default_initial_retransmit_time = std::chrono::milliseconds(100);
    constexpr int num_incremental_regions = 3;
    constexpr auto preferred_derp_absolute_diff = std::chrono::milliseconds(10);
    constexpr auto preferred_derp_frame_time = std::chrono::seconds(8);
    constexpr auto preferred_derp_keep_alive_timeout = std::chrono::seconds(120); // 2x derp.KeepAlive
}

// STUN transaction ID (96 bits)
class STUNTxID {
public:
    STUNTxID();
    explicit STUNTxID(const uint8_t* data);
    
    bool operator<(const STUNTxID& other) const;
    bool operator==(const STUNTxID& other) const;
    
    const uint8_t* data() const { return data_; }
    
private:
    uint8_t data_[12];
};

// STUN packet operations
namespace stun {
    std::vector<uint8_t> CreateRequest(const STUNTxID& tx_id);
    bool ParseResponse(const uint8_t* data, size_t size, 
                       STUNTxID& out_tx_id, 
                       asio::ip::udp::endpoint& out_endpoint);
}

// Client for performing network checks
class Client : public std::enable_shared_from_this<Client> {
public:
    explicit Client(asio::io_context& io_context);
    ~Client();
    
    // Configuration
    void SetVerbose(bool v) { verbose_ = v; }
    void SetSkipExternalNetwork(bool skip) { skip_external_network_ = skip; }
    void SetForcePreferredDerp(int region) { force_preferred_derp_ = region; }
    
    // Main netcheck operation
    void GetReport(std::shared_ptr<DERPMap> dm,
                   const GetReportOpts& opts,
                   std::function<void(std::shared_ptr<Report>, std::error_code)> callback);
    
    // For standalone operation - receive STUN packets
    void ReceiveStunPacket(const uint8_t* data, size_t size,
                           const asio::ip::udp::endpoint& from);
    
    // Make next report full (non-incremental)
    void MakeNextReportFull() {
        std::lock_guard<std::mutex> lock(mutex_);
        next_full_ = true;
    }
    
private:
    struct ReportState;
    
    // Probe execution
    void RunProbe(std::shared_ptr<ReportState> rs,
                  std::shared_ptr<DERPMap> dm,
                  const Probe& probe,
                  std::function<void()> cancel_set);
    
    void ExecuteProbe(std::shared_ptr<ReportState> rs,
                      std::shared_ptr<DERPMap> dm,
                      const Probe& probe,
                      std::shared_ptr<DERPNode> node,
                      std::function<void()> cancel_set);
    
    // Helper methods
    std::optional<asio::ip::udp::endpoint> NodeAddrPort(
        std::shared_ptr<DERPNode> node, int port, ProbeProto proto);
    
    bool ProbeWouldHelp(std::shared_ptr<ReportState> rs,
                         const Probe& probe,
                         std::shared_ptr<DERPNode> node);
    
    // IMPORTANT: This function signature was updated to include 'dm' parameter
    // Make sure you have the latest version of this file!
    void AddNodeLatency(std::shared_ptr<ReportState> rs,
                         std::shared_ptr<DERPMap> dm,  // <-- Added parameter
                         std::shared_ptr<DERPNode> node,
                         const asio::ip::udp::endpoint& endpoint,
                         duration latency);
    
    void StopProbes(std::shared_ptr<ReportState> rs);
    
    void FinishAndStoreReport(std::shared_ptr<ReportState> rs,
                                std::shared_ptr<DERPMap> dm);
    
    void StartReceiveV4();
    void StartReceiveV6();
    
    void AddReportHistoryAndSetPreferredDerp(
        std::shared_ptr<ReportState> rs,
        std::shared_ptr<Report> report,
        std::shared_ptr<DERPMap> dm);
    
    void LogConciseReport(const Report& report, const DERPMap& dm);
    
    int EnoughRegions() const {
        return verbose_ ? 100 : 3;
    }
    
    // Asio context
    asio::io_context& io_context_;
    
    // UDP socket for STUN
    std::unique_ptr<asio::ip::udp::socket> udp_socket_v4_;
    std::unique_ptr<asio::ip::udp::socket> udp_socket_v6_;
    
    // State
    mutable std::mutex mutex_;
    bool verbose_ = false;
    bool skip_external_network_ = false;
    bool next_full_ = true;
    int force_preferred_derp_ = 0;
    time_point last_full_;
    
    std::shared_ptr<Report> last_report_;
    std::map<time_point, std::shared_ptr<Report>> prev_reports_;
    std::shared_ptr<ReportState> cur_state_;
};

// Report state for a single GetReport invocation
struct Client::ReportState {
    std::shared_ptr<Client> client;
    time_point start;
    GetReportOpts opts;
    bool incremental = false;
    
    std::shared_ptr<Report> report;
    std::map<STUNTxID, std::function<void(asio::ip::udp::endpoint)>> in_flight;
    asio::ip::udp::endpoint got_ep4;
    
    mutable std::mutex mutex;
    std::vector<std::unique_ptr<asio::steady_timer>> timers;
    
    bool stop_probes_flag = false;
    std::function<void(std::shared_ptr<Report>, std::error_code)> callback;
    
    ReportState(std::shared_ptr<Client> c) 
        : client(c), start(steady_clock::now()), report(std::make_shared<Report>()) {
        report->now = start;
    }
    
    bool any_udp() const {
        std::lock_guard<std::mutex> lock(mutex);
        return report->udp;
    }
    
    bool have_region_latency(int region_id) const {
        std::lock_guard<std::mutex> lock(mutex);
        return report->region_latency.find(region_id) != report->region_latency.end();
    }
};

// Probe plan generation
ProbePlan MakeProbePlan(const DERPMap& dm,
                         const InterfaceState& if_state,
                         const Report* last,
                         int preferred_derp);

ProbePlan make_probe_plan_initial(const DERPMap& dm,
                                 const InterfaceState& if_state);

// Helper functions
std::vector<std::shared_ptr<DERPRegion>> sort_regions(
    const DERPMap& dm,
    const Report* last,
    int preferred_derp);

std::shared_ptr<DERPNode> NamedNode(const DERPMap& dm, const std::string& name);

bool region_has_derp_node(const DERPRegion& region);

duration MaxDurationValue(const std::map<int, duration>& m);

void UpdateLatency(std::map<int, duration>& m, int region_id, duration d);

} // namespace netcheck
