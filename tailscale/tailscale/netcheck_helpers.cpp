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
#include <algorithm>
//#include <iostream>
//#include <sstream>
//#include <iomanip>

namespace netcheck {

// Helper functions
std::shared_ptr<DERPNode> NamedNode(const DERPMap& dm, const std::string& name) {
    for (const auto& [_, region] : dm.regions) {
        for (const auto& node : region->nodes) {
            if (node->name == name) {
                return node;
            }
        }
    }
    return nullptr;
}

bool RegionHasDerpNode(const DERPRegion& region) {
    for (const auto& node : region.nodes) {
        if (!node->stun_only) {
            return true;
        }
    }
    return false;
}

duration MaxDurationValue(const std::map<int, duration>& m) {
    duration max_val = duration::zero();
    for (const auto& [_, d] : m) {
        if (d > max_val) {
            max_val = d;
        }
    }
    return max_val;
}

void UpdateLatency(std::map<int, duration>& m, int region_id, duration d) {
    auto it = m.find(region_id);
    if (it == m.end() || d < it->second) {
        m[region_id] = d;
    }
}

std::vector<std::shared_ptr<DERPRegion>> SortRegions(
    const DERPMap& dm,
    const Report* last,
    int preferred_derp) {
    
    std::vector<std::shared_ptr<DERPRegion>> regions;
    
    for (const auto& [_, reg] : dm.regions) {
        if (reg->no_measure_no_home) {
            continue;
        }
        if (reg->avoid && reg->region_id != preferred_derp) {
            continue;
        }
        regions.push_back(reg);
    }
    
    // Sort by latency
    std::sort(regions.begin(), regions.end(),
        [last](const auto& a, const auto& b) {
            if (!last) return false;
            
            auto da = last->region_latency.find(a->region_id);
            auto db = last->region_latency.find(b->region_id);
            
            duration lat_a = (da != last->region_latency.end()) ? 
                           da->second : duration::max();
            duration lat_b = (db != last->region_latency.end()) ? 
                           db->second : duration::max();
            
            // Non-zero sorts before zero
            if (lat_b == duration::max() && lat_a != duration::max()) {
                return true;
            }
            if (lat_a == duration::max()) {
                return false;
            }
            return lat_a < lat_b;
        });
    
    return regions;
}

bool NodeMightV4(const DERPNode& node) {
    if (node.ipv4.empty()) return true;
    std::error_code ec;
    auto addr = asio::ip::make_address(node.ipv4, ec);
    return !ec && addr.is_v4();
}

bool NodeMightV6(const DERPNode& node) {
    if (node.ipv6.empty()) return true;
    std::error_code ec;
    auto addr = asio::ip::make_address(node.ipv6, ec);
    return !ec && addr.is_v6();
}

ProbePlan MakeProbePlanInitial(const DERPMap& dm,
                                 const InterfaceState& if_state) {
    ProbePlan plan;
    
    for (const auto& [_, reg] : dm.regions) {
        if (reg->no_measure_no_home || reg->nodes.empty()) {
            continue;
        }
        
        std::vector<Probe> p4, p6;
        
        for (int try_num = 0; try_num < 3; try_num++) {
            auto& node = reg->nodes[try_num % reg->nodes.size()];
            auto delay = try_num * constants::default_initial_retransmit_time;
            
            if (node->ipv4 != "none" && 
                ((if_state.have_v4 && NodeMightV4(*node)) || node->IsTestNode())) {
                p4.push_back({delay, node->name, ProbeProto::IPv4, duration::zero()});
            }
            
            if (node->ipv6 != "none" && 
                ((if_state.have_v6 && NodeMightV6(*node)) || node->IsTestNode())) {
                p6.push_back({delay, node->name, ProbeProto::IPv6, duration::zero()});
            }
        }
        
        if (!p4.empty()) {
            plan["region-" + std::to_string(reg->region_id) + "-v4"] = p4;
        }
        if (!p6.empty()) {
            plan["region-" + std::to_string(reg->region_id) + "-v6"] = p6;
        }
    }
    
    return plan;
}

ProbePlan MakeProbePlan(const DERPMap& dm,
                         const InterfaceState& if_state,
                         const Report* last,
                         int preferred_derp) {
    if (!last || last->region_latency.empty()) {
        return MakeProbePlanInitial(dm, if_state);
    }
    
    ProbePlan plan;
    
    bool have_v6_if = if_state.have_v6;
    bool have_v4_if = if_state.have_v4;
    
    bool had_v4 = !last->region_v4_latency.empty();
    bool had_v6 = !last->region_v6_latency.empty();
    bool had_both = have_v6_if && had_v4 && had_v6;
    
    bool plan_contains_home = (preferred_derp == 0);
    
    auto sorted_regions = SortRegions(dm, last, preferred_derp);
    
    for (size_t ri = 0; ri < sorted_regions.size(); ri++) {
        auto& reg = sorted_regions[ri];
        bool reg_is_home = (reg->region_id == preferred_derp);
        
        if (ri >= constants::num_incremental_regions) {
            if (plan_contains_home) {
                break;
            }
            if (!reg_is_home) {
                continue;
            }
        }
        
        std::vector<Probe> p4, p6;
        bool do_v4 = have_v4_if;
        bool do_v6 = have_v6_if;
        
        int tries = 1;
        bool is_fastest_two = (ri < 2);
        
        if (is_fastest_two || reg_is_home) {
            tries = 2;
        } else if (had_both) {
            // Alternate between v4 and v6 for dual stack
            if (ri % 2 == 0) {
                do_v4 = true;
                do_v6 = false;
            } else {
                do_v4 = false;
                do_v6 = true;
            }
        }
        
        if (!reg_is_home && !is_fastest_two && !had_v6) {
            do_v6 = false;
        }
        
        if (reg_is_home) {
            tries = 4;
            plan_contains_home = true;
        }
        
        for (int try_num = 0; try_num < tries; try_num++) {
            if (reg->nodes.empty()) {
                continue;
            }
            if (try_num != 0 && !had_v6) {
                do_v6 = false;
            }
            
            auto& node = reg->nodes[try_num % reg->nodes.size()];
            
            // Calculate delay based on previous latency
            auto it = last->region_latency.find(reg->region_id);
            duration prev_latency = (it != last->region_latency.end()) ?
                it->second * 120 / 100 : constants::default_active_retransmit_time;
            
            auto delay = try_num * prev_latency;
            if (try_num > 1) {
                delay += std::chrono::milliseconds(try_num * 50);
            }
            
            if (node->ipv4 != "none" && (do_v4 || node->IsTestNode())) {
                p4.push_back({delay, node->name, ProbeProto::IPv4, duration::zero()});
            }
            if (node->ipv6 != "none" && (do_v6 || node->IsTestNode())) {
                p6.push_back({delay, node->name, ProbeProto::IPv6, duration::zero()});
            }
        }
        
        if (!p4.empty()) {
            plan["region-" + std::to_string(reg->region_id) + "-v4"] = p4;
        }
        if (!p6.empty()) {
            plan["region-" + std::to_string(reg->region_id) + "-v6"] = p6;
        }
    }
    
    return plan;
}

void Client::AddReportHistoryAndSetPreferredDerp(
    std::shared_ptr<ReportState> rs,
    std::shared_ptr<Report> report,
    std::shared_ptr<DERPMap> dm) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    int prev_derp = 0;
    if (last_report_) {
        prev_derp = last_report_->preferred_derp;
    }
    
    // Build map of best recent latencies
    std::map<int, duration> best_recent;
    auto now = steady_clock::now();
    
    for (const auto& [time, pr] : prev_reports_) {
        if (std::chrono::duration_cast<std::chrono::minutes>(
            now - time).count() <= 5) {
            for (const auto& [region_id, d] : pr->region_latency) {
                auto it = best_recent.find(region_id);
                if (it == best_recent.end() || d < it->second) {
                    best_recent[region_id] = d;
                }
            }
        }
    }
    
    // Find best region from current report
    duration best_any = duration::max();
    duration old_region_cur_latency = duration::zero();
    
    for (const auto& [region_id, d] : report->region_latency) {
        if (region_id == prev_derp) {
            old_region_cur_latency = d;
        }
        
        auto best = best_recent[region_id];
        if (report->preferred_derp == 0 || best < best_any) {
            best_any = best;
            report->preferred_derp = region_id;
        }
    }
    
    // Apply stickiness to current DERP
    bool keep_old = false;
    bool changing_preferred = (prev_derp != 0 && report->preferred_derp != prev_derp);
    
    bool heard_from_old_recently = false;
    if (changing_preferred && rs->opts.GetLastDerpActivity) {
        auto last_heard = rs->opts.GetLastDerpActivity(prev_derp);
        heard_from_old_recently = (last_heard >= rs->start) ||
            (last_heard >= now - constants::preferred_derp_frame_time);
    }
    
    bool old_region_accessible = (old_region_cur_latency != duration::zero()) || 
                                 heard_from_old_recently;
    
    if (changing_preferred && old_region_accessible) {
        if (old_region_cur_latency - best_any < constants::preferred_derp_absolute_diff) {
            keep_old = true;
        }
        if (best_any > old_region_cur_latency * 2 / 3) {
            keep_old = true;
        }
    }
    
    if (keep_old) {
        report->preferred_derp = prev_derp;
    }
    
    // Handle forced DERP
    if (force_preferred_derp_ != 0) {
        bool have_latency = report->region_latency.find(force_preferred_derp_) != 
                          report->region_latency.end();
        bool recent_activity = false;
        
        if (rs->opts.GetLastDerpActivity) {
            auto last_heard = rs->opts.GetLastDerpActivity(force_preferred_derp_);
            recent_activity = (last_heard >= rs->start) ||
                (last_heard >= now - constants::preferred_derp_frame_time);
        }
        
        if (have_latency || recent_activity) {
            report->preferred_derp = force_preferred_derp_;
        }
    }
    
    // Keep current DERP if no latency data but recent keepalive
    if (report->preferred_derp == 0 && rs->opts.GetLastDerpActivity) {
        auto last_heard = rs->opts.GetLastDerpActivity(prev_derp);
        if (last_heard >= now - constants::preferred_derp_keep_alive_timeout) {
            report->preferred_derp = prev_derp;
        }
    }
}

void Client::LogConciseReport(const Report& report, const DERPMap& dm) {

}

} // namespace netcheck
