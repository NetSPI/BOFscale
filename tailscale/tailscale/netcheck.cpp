// Windows compatibility - must be defined before any includes
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include "netcheck.hpp"
#include "stun.hpp"
#include <algorithm>

namespace netcheck {

// Report implementation
std::pair<std::vector<asio::ip::udp::endpoint>, 
          std::vector<asio::ip::udp::endpoint>> 
Report::GetGlobalAddrs() const {
    std::vector<asio::ip::udp::endpoint> v4, v6;
    
    // Add best latency entries first
    if (global_v4.port() != 0) {
        v4.push_back(global_v4);
    }
    if (global_v6.port() != 0) {
        v6.push_back(global_v6);
    }
    
    // Add entries with multiple observations
    for (const auto& [ipp, count] : global_v4_counters) {
        if (ipp != global_v4 && count > 1) {
            v4.push_back(ipp);
        }
    }
    for (const auto& [ipp, count] : global_v6_counters) {
        if (ipp != global_v6 && count > 1) {
            v6.push_back(ipp);
        }
    }
    
    return {v4, v6};
}

// Client implementation
Client::Client(asio::io_context& io_context)
    : io_context_(io_context), last_full_(steady_clock::now()) {
}

Client::~Client() {
    // Cleanup
}

void Client::ReceiveStunPacket(const uint8_t* data, size_t size,
                                const asio::ip::udp::endpoint& from) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!cur_state_) {
        return;
    }
    
    STUNTxID tx_id;
    asio::ip::udp::endpoint addr_port;
    
    if (!stun::ParseResponse(data, size, tx_id, addr_port)) {
        return;
    }
    
    // Find and extract callback while holding lock
    std::function<void(asio::ip::udp::endpoint)> callback;
    {
        std::lock_guard<std::mutex> state_lock(cur_state_->mutex);
        auto it = cur_state_->in_flight.find(tx_id);
        if (it != cur_state_->in_flight.end()) {
            callback = std::move(it->second);
            cur_state_->in_flight.erase(it);
        }
    } // state_lock released here
    
    // Execute callback without locks
    if (callback) {
        callback(addr_port);
    }
}

void Client::StartReceiveV4() {
    if (!udp_socket_v4_ || !udp_socket_v4_->is_open()) {
        return;
    }
    
    // Allocate buffer for receiving
    auto buffer = std::make_shared<std::array<uint8_t, 2048>>();
    auto sender_endpoint = std::make_shared<asio::ip::udp::endpoint>();
    
    udp_socket_v4_->async_receive_from(
        asio::buffer(*buffer), *sender_endpoint,
        [this, buffer, sender_endpoint](const std::error_code& ec, std::size_t bytes_received) {
            if (!ec && bytes_received > 0) {
                ReceiveStunPacket(buffer->data(), bytes_received, *sender_endpoint);
            }
            // Continue receiving
            if (udp_socket_v4_ && udp_socket_v4_->is_open()) {
                StartReceiveV4();
            }
        });
}

void Client::StartReceiveV6() {
    if (!udp_socket_v6_ || !udp_socket_v6_->is_open()) {
        return;
    }
    
    // Allocate buffer for receiving
    auto buffer = std::make_shared<std::array<uint8_t, 2048>>();
    auto sender_endpoint = std::make_shared<asio::ip::udp::endpoint>();
    
    udp_socket_v6_->async_receive_from(
        asio::buffer(*buffer), *sender_endpoint,
        [this, buffer, sender_endpoint](const std::error_code& ec, std::size_t bytes_received) {
            if (!ec && bytes_received > 0) {
                ReceiveStunPacket(buffer->data(), bytes_received, *sender_endpoint);
            }
            // Continue receiving
            if (udp_socket_v6_ && udp_socket_v6_->is_open()) {
                StartReceiveV6();
            }
        });
}

void Client::GetReport(std::shared_ptr<DERPMap> dm,
                       const GetReportOpts& opts,
                       std::function<void(std::shared_ptr<Report>, std::error_code)> callback) {
    if (!dm) {
        asio::post(io_context_, [callback]() {
            callback(nullptr, std::make_error_code(std::errc::invalid_argument));
        });
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (cur_state_) {
        asio::post(io_context_, [callback]() {
            callback(nullptr, std::make_error_code(std::errc::operation_in_progress));
        });
        return;
    }
    
    auto now = steady_clock::now();
    auto rs = std::make_shared<ReportState>(shared_from_this());
    rs->start = now;
    rs->opts = opts;
    rs->callback = callback;
    
    std::shared_ptr<Report> last = last_report_;
    int preferred_derp = last ? last->preferred_derp : 0;
    
    bool do_full = next_full_ || 
                   std::chrono::duration_cast<std::chrono::minutes>(
                       now - last_full_).count() > 5;
    
    if (!do_full && last && !last->udp && last->captive_portal.equal_bool(true)) {
        do_full = true;
    }
    
    if (do_full) {
        last = nullptr;
        next_full_ = false;
        last_full_ = now;
    }
    
    rs->incremental = (last != nullptr);
    cur_state_ = rs;
    
    // Get interface state
    InterfaceState if_state;
    if_state.have_v4 = true; // TODO: detect properly
    if_state.have_v6 = true; // TODO: detect properly
    
    // Check if IPv6 works
    std::error_code ec;
    asio::ip::udp::socket test_sock(io_context_);
    test_sock.open(asio::ip::udp::v6(), ec);
    if (!ec) {
        test_sock.bind(asio::ip::udp::endpoint(
            asio::ip::make_address_v6("::1"), 0), ec);
        rs->report->os_has_ipv6 = !ec;
        test_sock.close();
    }
    
    // Create probe plan
    ProbePlan plan;
    if (!opts.only_tcp443) {
        plan = MakeProbePlan(*dm, if_state, last.get(), preferred_derp);
    }
    
    // Execute probes
    size_t num_probe_sets = plan.size();
    auto remaining = std::make_shared<std::atomic<size_t>>(num_probe_sets);
    
    for (const auto& [name, probe_set] : plan) {
        asio::post(io_context_, [this, rs, dm, probe_set, remaining]() {
            auto cancel_called = std::make_shared<bool>(false);
            auto cancel_set = [cancel_called]() {
                *cancel_called = true;
            };
            
            for (const auto& probe : probe_set) {
                if (*cancel_called || rs->stop_probes_flag) {
                    break;
                }
                RunProbe(rs, dm, probe, cancel_set);
            }
            
            // Decrement counter but don't finish here
            // Let the timeout timer handle finishing
            --(*remaining);
        });
    }
    
    // Set timeout
    auto timeout_timer = std::make_unique<asio::steady_timer>(io_context_);
    timeout_timer->expires_after(constants::report_timeout);
    timeout_timer->async_wait([this, rs, dm](const std::error_code& ec) {
        if (!ec) {
            StopProbes(rs);
            FinishAndStoreReport(rs, dm);
        }
    });
    
    std::lock_guard<std::mutex> state_lock(rs->mutex);
    rs->timers.push_back(std::move(timeout_timer));
}

void Client::RunProbe(std::shared_ptr<ReportState> rs,
                      std::shared_ptr<DERPMap> dm,
                      const Probe& probe,
                      std::function<void()> cancel_set) {
    auto node = NamedNode(*dm, probe.node);
    if (!node) {
        return;
    }
    
    // Handle probe delay
    if (probe.delay > duration::zero()) {
        auto delay_timer = std::make_unique<asio::steady_timer>(io_context_);
        delay_timer->expires_after(probe.delay);
        delay_timer->async_wait([this, rs, dm, probe, node, cancel_set]
                                (const std::error_code& ec) {
            if (!ec && !rs->stop_probes_flag) {
                ExecuteProbe(rs, dm, probe, node, cancel_set);
            }
        });
        
        std::lock_guard<std::mutex> lock(rs->mutex);
        rs->timers.push_back(std::move(delay_timer));
        return;
    }
    
    ExecuteProbe(rs, dm, probe, node, cancel_set);
}

void Client::ExecuteProbe(std::shared_ptr<ReportState> rs,
                          std::shared_ptr<DERPMap> dm,
                          const Probe& probe,
                          std::shared_ptr<DERPNode> node,
                          std::function<void()> cancel_set) {
    if (!ProbeWouldHelp(rs, probe, node)) {
        cancel_set();
        return;
    }
    
    auto addr_opt = NodeAddrPort(node, node->stun_port, probe.proto);
    if (!addr_opt) {
        return;
    }
    
    asio::ip::udp::endpoint addr = *addr_opt;
    STUNTxID tx_id;
    auto req = stun::CreateRequest(tx_id);
    
    auto sent_time = steady_clock::now();
    
    // Register callback for response
    {
        std::lock_guard<std::mutex> lock(rs->mutex);
        rs->in_flight[tx_id] = [this, rs, dm, node, sent_time, cancel_set]
                                (const asio::ip::udp::endpoint& ipp) {
            auto latency = steady_clock::now() - sent_time;
            AddNodeLatency(rs, dm, node, ipp, latency);
            cancel_set();
        };
    }
    
    // Send STUN packet
    std::error_code ec;
    asio::ip::udp::socket* sock = nullptr;
    
    if (addr.address().is_v4()) {
        if (!udp_socket_v4_) {
            udp_socket_v4_ = std::make_unique<asio::ip::udp::socket>(io_context_);
            udp_socket_v4_->open(asio::ip::udp::v4(), ec);
            StartReceiveV4();  // Start async receive on v4 socket
        }
        sock = udp_socket_v4_.get();
        
        std::lock_guard<std::mutex> lock(rs->mutex);
        rs->report->ipv4_can_send = true;
    } else {
        if (!udp_socket_v6_) {
            udp_socket_v6_ = std::make_unique<asio::ip::udp::socket>(io_context_);
            udp_socket_v6_->open(asio::ip::udp::v6(), ec);
            StartReceiveV6();  // Start async receive on v6 socket
        }
        sock = udp_socket_v6_.get();
        
        std::lock_guard<std::mutex> lock(rs->mutex);
        rs->report->ipv6_can_send = true;
    }
    
    if (sock && sock->is_open()) {
        sock->send_to(asio::buffer(req), addr, 0, ec);
    }
}

std::optional<asio::ip::udp::endpoint> Client::NodeAddrPort(
    std::shared_ptr<DERPNode> node, int port, ProbeProto proto) {
    
    if (port < 0 || port > 65535) {
        return std::nullopt;
    }
    if (port == 0) {
        port = 3478; // Default STUN port
    }
    
    // Try test IP first
    if (!node->stun_test_ip.empty()) {
        std::error_code ec;
        auto addr = asio::ip::make_address(node->stun_test_ip, ec);
        if (!ec) {
            if ((proto == ProbeProto::IPv4 && addr.is_v4()) ||
                (proto == ProbeProto::IPv6 && addr.is_v6())) {
                return asio::ip::udp::endpoint(addr, port);
            }
        }
    }
    
    // Try configured IPs
    if (proto == ProbeProto::IPv4 && !node->ipv4.empty() && node->ipv4 != "none") {
        std::error_code ec;
        auto addr = asio::ip::make_address(node->ipv4, ec);
        if (!ec && addr.is_v4()) {
            return asio::ip::udp::endpoint(addr, port);
        }
    }
    
    if (proto == ProbeProto::IPv6 && !node->ipv6.empty() && node->ipv6 != "none") {
        std::error_code ec;
        auto addr = asio::ip::make_address(node->ipv6, ec);
        if (!ec && addr.is_v6()) {
            return asio::ip::udp::endpoint(addr, port);
        }
    }
    
    // TODO: DNS lookup if no IP configured
    
    return std::nullopt;
}

bool Client::ProbeWouldHelp(std::shared_ptr<ReportState> rs,
                             const Probe& probe,
                             std::shared_ptr<DERPNode> node) {
    std::lock_guard<std::mutex> lock(rs->mutex);
    
    // If we don't know about this region yet, probe would help
    if (rs->report->region_latency.find(node->region_id) == 
        rs->report->region_latency.end()) {
        return true;
    }
    
    // If probe is IPv6 and we have no IPv6 results, would help
    if (probe.proto == ProbeProto::IPv6 && rs->report->region_v6_latency.empty()) {
        return true;
    }
    
    // If probe is IPv4 and we don't know if mapping varies, would help
    if (probe.proto == ProbeProto::IPv4 && !rs->report->mapping_varies_by_dest_ip.has_value()) {
        return true;
    }
    
    return false;
}

void Client::AddNodeLatency(std::shared_ptr<ReportState> rs,
                             std::shared_ptr<DERPMap> dm,
                             std::shared_ptr<DERPNode> node,
                             const asio::ip::udp::endpoint& endpoint,
                             duration latency) {
    std::lock_guard<std::mutex> lock(rs->mutex);
    auto& report = rs->report;
    
    report->udp = true;
    UpdateLatency(report->region_latency, node->region_id, latency);
    
    // Check if we've heard from enough regions
    if (report->region_latency.size() == static_cast<size_t>(EnoughRegions())) {
        auto timeout = MaxDurationValue(report->region_latency);
        if (!rs->incremental) {
            timeout *= 2;
        }
        
        // Create timer for early termination
        auto timer = std::make_unique<asio::steady_timer>(io_context_);
        timer->expires_after(timeout);
        timer->async_wait([this, rs, dm](const std::error_code& ec) {
            if (!ec) {
                StopProbes(rs);
                // Schedule finish with grace period for in-flight responses
                asio::post(io_context_, [this, rs, dm]() {
                    auto finish_timer = std::make_unique<asio::steady_timer>(io_context_);
                    finish_timer->expires_after(std::chrono::milliseconds(100));
                    finish_timer->async_wait([this, rs, dm](const std::error_code& ec2) {
                        if (!ec2) {
                            FinishAndStoreReport(rs, dm);
                        }
                    });
                    
                    std::lock_guard<std::mutex> lock(rs->mutex);
                    rs->timers.push_back(std::move(finish_timer));
                });
            }
        });
        
        // Add timer to list while we have the lock
        rs->timers.push_back(std::move(timer));
    }
    
    if (endpoint.address().is_v6()) {
        UpdateLatency(report->region_v6_latency, node->region_id, latency);
        report->ipv6 = true;
        report->global_v6 = endpoint;
        report->global_v6_counters[endpoint]++;
    } else if (endpoint.address().is_v4()) {
        UpdateLatency(report->region_v4_latency, node->region_id, latency);
        report->ipv4 = true;
        report->global_v4_counters[endpoint]++;
        
        if (rs->got_ep4.port() == 0) {
            rs->got_ep4 = endpoint;
            report->global_v4 = endpoint;
        } else {
            if (rs->got_ep4 != endpoint) {
                report->mapping_varies_by_dest_ip.set(true);
            } else if (!report->mapping_varies_by_dest_ip.has_value()) {
                report->mapping_varies_by_dest_ip.set(false);
            }
        }
    }
}

void Client::StopProbes(std::shared_ptr<ReportState> rs) {
    std::lock_guard<std::mutex> lock(rs->mutex);
    rs->stop_probes_flag = true;
}

void Client::FinishAndStoreReport(std::shared_ptr<ReportState> rs,
                                    std::shared_ptr<DERPMap> dm) {
    auto report = std::make_shared<Report>(*rs->report);
    
    AddReportHistoryAndSetPreferredDerp(rs, report, dm);
    LogConciseReport(*report, *dm);
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_report_ = report;
        prev_reports_[report->now] = report;
        
        // Clean old reports
        auto now = steady_clock::now();
        for (auto it = prev_reports_.begin(); it != prev_reports_.end();) {
            if (std::chrono::duration_cast<std::chrono::minutes>(
                now - it->first).count() > 5) {
                it = prev_reports_.erase(it);
            } else {
                ++it;
            }
        }
        
        cur_state_ = nullptr;
    }
    
    // Call user callback
    if (rs->callback) {
        rs->callback(report, std::error_code());
    }
}

} // namespace netcheck
