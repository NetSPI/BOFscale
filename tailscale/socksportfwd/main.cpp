#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <csignal>
#include <cstdarg>
#include <map>
#include <beacon.h>
#include <asio.hpp>

using asio::error_code;

const uint8_t SOCKS5_VERSION = 0x05;
const uint8_t SOCKS5_AUTH_NONE = 0x00;
const uint8_t SOCKS5_CMD_CONNECT = 0x01;
const uint8_t SOCKS5_ATYP_IPV4 = 0x01;
const uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
const uint8_t SOCKS5_ATYP_IPV6 = 0x04;
const uint8_t SOCKS5_REP_SUCCESS = 0x00;

const size_t BUFFER_SIZE = 8192;

struct Config {
    std::string listen_address;
    uint16_t listen_port;
    std::string target_host;
    uint16_t target_port;
    std::string socks5_host;
    uint16_t socks5_port;

    Config() : listen_address("0.0.0.0"), listen_port(0),
        target_port(80), socks5_host("localhost"), socks5_port(1080) {
    }
};

class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(asio::ip::tcp::socket client_socket, const Config& config)
        : client_socket_(std::move(client_socket)),
        socks_socket_(client_socket_.get_executor()),
        config_(config),
        resolver_(client_socket_.get_executor()) {
    }

    void start() {
        // Resolve SOCKS5 proxy address and connect
        auto self = shared_from_this();
        resolver_.async_resolve(
            config_.socks5_host,
            std::to_string(config_.socks5_port),
            [self](const error_code& ec, asio::ip::tcp::resolver::results_type results) {
                if (!ec) {
                    self->connect_to_socks(results);
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to resolve SOCKS5 proxy: %s\n", ec.message().c_str());
                }
            });
    }

private:
    void connect_to_socks(const asio::ip::tcp::resolver::results_type& endpoints) {
        auto self = shared_from_this();
        asio::async_connect(
            socks_socket_,
            endpoints,
            [self](const error_code& ec, const asio::ip::tcp::endpoint&) {
                if (!ec) {
                    BeaconPrintf(CALLBACK_OUTPUT, "Connected to SOCKS5 proxy\n");
                    self->send_auth_methods();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to connect to SOCKS5 proxy: %s\n", ec.message().c_str());
                }
            });
    }

    void send_auth_methods() {

        socks_write_buffer_ = { SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE };

        auto self = shared_from_this();
        asio::async_write(
            socks_socket_,
            asio::buffer(socks_write_buffer_),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    self->receive_auth_method();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to send auth methods: %s\n", ec.message().c_str());
                }
            });
    }

    void receive_auth_method() {
        auto self = shared_from_this();
        socks_read_buffer_.resize(2);
        asio::async_read(
            socks_socket_,
            asio::buffer(socks_read_buffer_),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    if (self->socks_read_buffer_[0] != SOCKS5_VERSION) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid SOCKS5 version\n");
                        return;
                    }

                    uint8_t method = self->socks_read_buffer_[1];
                    if (method == SOCKS5_AUTH_NONE) {
                        self->send_connect_request();
                    }
                    else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] SOCKS5 proxy requires authentication (not supported)\n");
                    }
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive auth method: %s\n", ec.message().c_str());
                }
            });
    }

    void send_connect_request() {
        // Build CONNECT request
        socks_write_buffer_.clear();
        socks_write_buffer_.push_back(SOCKS5_VERSION);
        socks_write_buffer_.push_back(SOCKS5_CMD_CONNECT);
        socks_write_buffer_.push_back(0x00);

        // Try to parse as IPv4
        asio::ip::address addr;
        error_code ec;
        addr = asio::ip::make_address(config_.target_host, ec);

        if (!ec && addr.is_v4()) {
            // IPv4 address
            socks_write_buffer_.push_back(SOCKS5_ATYP_IPV4);
            auto bytes = addr.to_v4().to_bytes();
            socks_write_buffer_.insert(socks_write_buffer_.end(), bytes.begin(), bytes.end());
        }
        else if (!ec && addr.is_v6()) {
            // IPv6 address
            socks_write_buffer_.push_back(SOCKS5_ATYP_IPV6);
            auto bytes = addr.to_v6().to_bytes();
            socks_write_buffer_.insert(socks_write_buffer_.end(), bytes.begin(), bytes.end());
        }
        else {
            // Domain name
            socks_write_buffer_.push_back(SOCKS5_ATYP_DOMAIN);
            socks_write_buffer_.push_back(static_cast<uint8_t>(config_.target_host.length()));
            socks_write_buffer_.insert(socks_write_buffer_.end(),
                config_.target_host.begin(),
                config_.target_host.end());
        }

        // Add port (network byte order)
        socks_write_buffer_.push_back(static_cast<uint8_t>(config_.target_port >> 8));
        socks_write_buffer_.push_back(static_cast<uint8_t>(config_.target_port & 0xFF));

        auto self = shared_from_this();
        asio::async_write(
            socks_socket_,
            asio::buffer(socks_write_buffer_),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    self->receive_connect_response();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to send CONNECT request: %s\n", ec.message().c_str());
                }
            });
    }

    void receive_connect_response() {
        auto self = shared_from_this();
        socks_read_buffer_.resize(4);
        asio::async_read(
            socks_socket_,
            asio::buffer(socks_read_buffer_),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    if (self->socks_read_buffer_[0] != SOCKS5_VERSION) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid SOCKS5 version in CONNECT response\n");
                        return;
                    }

                    if (self->socks_read_buffer_[1] != SOCKS5_REP_SUCCESS) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] SOCKS5 CONNECT failed with code: %d\n",
                            static_cast<int>(self->socks_read_buffer_[1]));
                        return;
                    }

                    uint8_t atyp = self->socks_read_buffer_[3];
                    self->receive_bind_address(atyp);
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive CONNECT response: %s\n", ec.message().c_str());
                }
            });
    }

    void receive_bind_address(uint8_t atyp) {
        auto self = shared_from_this();
        size_t addr_size = 0;

        if (atyp == SOCKS5_ATYP_IPV4) {
            addr_size = 6; // 4 bytes IP + 2 bytes port
        }
        else if (atyp == SOCKS5_ATYP_IPV6) {
            addr_size = 18; // 16 bytes IP + 2 bytes port
        }
        else if (atyp == SOCKS5_ATYP_DOMAIN) {
            // Need to read domain length first
            socks_read_buffer_.resize(1);
            asio::async_read(
                socks_socket_,
                asio::buffer(socks_read_buffer_),
                [self](const error_code& ec, std::size_t) {
                    if (!ec) {
                        size_t domain_len = self->socks_read_buffer_[0];
                        self->receive_bind_address_domain(domain_len);
                    }
                    else {
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive bind address length: %s\n", ec.message().c_str());
                    }
                });
            return;
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Unknown SOCKS5 address type: %d\n", static_cast<int>(atyp));
            return;
        }

        socks_read_buffer_.resize(addr_size);
        asio::async_read(
            socks_socket_,
            asio::buffer(socks_read_buffer_),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    BeaconPrintf(CALLBACK_OUTPUT, "SOCKS5 connection established to target\n");
                    self->start_relay();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive bind address: %s\n", ec.message().c_str());
                }
            });
    }

    void receive_bind_address_domain(size_t domain_len) {
        auto self = shared_from_this();
        socks_read_buffer_.resize(domain_len + 2); // domain + 2 bytes port
        asio::async_read(
            socks_socket_,
            asio::buffer(socks_read_buffer_),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    BeaconPrintf(CALLBACK_OUTPUT, "SOCKS5 connection established to target\n");
                    self->start_relay();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive bind address domain: %s\n", ec.message().c_str());
                }
            });
    }

    void start_relay() {
        // Start bidirectional relay
        read_from_client();
        read_from_socks();
    }

    void read_from_client() {
        auto self = shared_from_this();
        client_socket_.async_read_some(
            asio::buffer(client_read_buffer_),
            [self](const error_code& ec, std::size_t bytes_transferred) {
                if (!ec) {
                    self->write_to_socks(bytes_transferred);
                }
                else if (ec != asio::error::eof) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Error reading from client: %s\n", ec.message().c_str());
                }
                // On EOF or error, close the connection
                if (ec) {
                    self->close_sockets();
                }
            });
    }

    void write_to_socks(std::size_t length) {
        auto self = shared_from_this();
        asio::async_write(
            socks_socket_,
            asio::buffer(client_read_buffer_, length),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    self->read_from_client();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Error writing to SOCKS: %s\n", ec.message().c_str());
                    self->close_sockets();
                }
            });
    }

    void read_from_socks() {
        auto self = shared_from_this();
        socks_socket_.async_read_some(
            asio::buffer(socks_relay_buffer_),
            [self](const error_code& ec, std::size_t bytes_transferred) {
                if (!ec) {
                    self->write_to_client(bytes_transferred);
                }
                else if (ec != asio::error::eof) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Error reading from SOCKS: %s\n", ec.message().c_str());
                }
                // On EOF or error, close the connection
                if (ec) {
                    self->close_sockets();
                }
            });
    }

    void write_to_client(std::size_t length) {
        auto self = shared_from_this();
        asio::async_write(
            client_socket_,
            asio::buffer(socks_relay_buffer_, length),
            [self](const error_code& ec, std::size_t) {
                if (!ec) {
                    self->read_from_socks();
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Error writing to client: %s\n", ec.message().c_str());
                    self->close_sockets();
                }
            });
    }

    void close_sockets() {
        error_code ec;
        client_socket_.close(ec);
        socks_socket_.close(ec);
    }

    asio::ip::tcp::socket client_socket_;
    asio::ip::tcp::socket socks_socket_;
    asio::ip::tcp::resolver resolver_;
    const Config& config_;

    std::vector<uint8_t> socks_write_buffer_;
    std::vector<uint8_t> socks_read_buffer_;
    uint8_t client_read_buffer_[BUFFER_SIZE];
    uint8_t socks_relay_buffer_[BUFFER_SIZE];
};

class Server {
public:
    Server(asio::io_context& io_context, const Config& config)
        : io_context_(io_context),
        acceptor_(io_context),
        config_(config) {

        asio::ip::tcp::endpoint endpoint(
            asio::ip::make_address(config.listen_address),
            config.listen_port
        );

        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();

        BeaconPrintf(CALLBACK_OUTPUT, "Port forwarder listening on %s:%d\n",
            config.listen_address.c_str(), config.listen_port);
        BeaconPrintf(CALLBACK_OUTPUT, "Forwarding to %s:%d via SOCKS5 proxy %s:%d\n",
            config.target_host.c_str(), config.target_port,
            config.socks5_host.c_str(), config.socks5_port);

        start_accept();
    }

private:
    void start_accept() {
        acceptor_.async_accept(
            [this](const error_code& ec, asio::ip::tcp::socket socket) {
                if (!ec) {
                    BeaconPrintf(CALLBACK_OUTPUT, "Accepted connection from %s:%d\n",
                        socket.remote_endpoint().address().to_string().c_str(),
                        socket.remote_endpoint().port());

                    auto conn = std::make_shared<Connection>(std::move(socket), config_);
                    conn->start();
                }

                start_accept();
            });
    }

    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    const Config& config_;
};

void setup_windows_event_shutdown(asio::io_context& io_context, HANDLE shutdown_event) {

    auto timer = std::make_shared<asio::steady_timer>(io_context);
    auto check_event = std::make_shared<std::function<void(const error_code&)>>();
    *check_event = [&io_context, shutdown_event, timer, check_event](const error_code& ec) {
        if (!ec) {
            if (WaitForSingleObject(shutdown_event, 0) == WAIT_OBJECT_0) {
                BeaconPrintf(CALLBACK_OUTPUT, "Shutdown event signaled\n");
                io_context.stop();
                return;
            }
            timer->expires_after(std::chrono::milliseconds(500));
            timer->async_wait(*check_event);  
        }
        };
    timer->expires_after(std::chrono::milliseconds(500));
    timer->async_wait(*check_event);
  
}

std::map<std::string, std::string> GetBeaconArgs(datap* data) {

    std::map<std::string, std::string> args;
    std::string token;
    char* ptr;

    while ((ptr = BeaconDataExtract(data, nullptr)) != nullptr) {
        token = std::string(ptr);
        if (token.rfind("--", 0) != 0) {
            if (!args.contains("command"))
                args["command"] = token;
            else
                BeaconPrintf(CALLBACK_OUTPUT, "[!] multiple commands found within argument array, igoring: %s\n", token.c_str());

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
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] unexpected token after flag: %s\n", next.c_str());
            }
        }

        args[key] = value;
    }

    return args;
}

extern "C" __declspec(dllexport) void go(const char* data, int len) {

    Config config;
    datap args_data;

    if (data == nullptr || len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "No arguments provided\n");
        return;
    }

    BeaconDataParse(&args_data, (char*)data, len);
    auto args = GetBeaconArgs(&args_data);

    for (auto const& arg_pair : args) {

        auto& arg = arg_pair.first;
        auto& value = arg_pair.second;

        if (arg == "l") {
            config.listen_address = value;
        }
        else if (arg == "p") {
            config.listen_port = static_cast<uint16_t>(std::stoi(value));
        }
        else if (arg == "t") {
            config.target_host = value;
        }
        else if (arg == "tp") {
            config.target_port = static_cast<uint16_t>(std::stoi(value));
        }
        else if (arg == "s") {
            config.socks5_host = value;
        }
        else if (arg == "sp") {
            config.socks5_port = static_cast<uint16_t>(std::stoi(value));
        }
    }


    // Validate required parameters
    if (config.target_host.empty() || config.target_port == 0 ||
        config.socks5_host.empty()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Missing parameters: --t and --tp are mandatory\n");
        return;
    }

    if (config.listen_port == 0) {
        config.listen_port = config.target_port;
    }

    HANDLE shutdown_event = nullptr;    
    if (BeaconGetStopJobEvent != nullptr) {
        shutdown_event = BeaconGetStopJobEvent();
        if (shutdown_event == nullptr) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get stop event from beacon API");
            return;
        }
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] This BOF only supports execution via the async API");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Use your C2 built in features to stop the task (async event handle 0x%x)\n", shutdown_event);

    try {
        asio::io_context io_context;
        setup_windows_event_shutdown(io_context, shutdown_event);
        Server server(io_context, config);
        io_context.run();
        BeaconPrintf(CALLBACK_OUTPUT, "Server shut down\n"); 
    }
    catch (std::exception& e) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] %s\n", e.what());
        return;
    }

    return;
}

BEACON_MAIN("zzzzzzzzzzzz", go)