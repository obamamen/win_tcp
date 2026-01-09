/* ================================== *\
 @file     win_tcp.hpp
 @project  win_tcp
 @author   moosm
 @date     1/8/2026
*\ ================================== */

#ifndef WIN_TCP_WIN_TCP_HPP
#define WIN_TCP_WIN_TCP_HPP

#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <ostream>
#include <vector>

// socket.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bits/codecvt.h>

namespace win_tcp::core
{
    using internal_socket = SOCKET;
    constexpr internal_socket invalid_socket = (internal_socket)INVALID_SOCKET;

    enum address_family : int
    {
        invalid = -1,

        ipv4 = AF_INET,
        ipv6 = AF_INET6,
    };

    inline void log_wsa_error(const std::string& name = "")
    {
        const auto s = std::system_category().message(WSAGetLastError());
        std::cerr << name << " : " << s << std::endl;
    }

    struct connection_info
    {
        std::string ip_address{};
        uint16_t port{0};
        address_family address_family{address_family::invalid};

        std::string to_string() const
        {
            if ( !this->is_valid() )
            {
                return std::string{"(invalid)"};
            }

            if (address_family == address_family::ipv6)
                return "[" + ip_address + "]:" + std::to_string(port);

            return ip_address + ":" + std::to_string(port);
        }

        bool is_valid() const
        {
            if (this->address_family == address_family::invalid) return false;
            if (this->ip_address.empty()) return false;

            return true;
        }
    };


    class tcp_socket
    {
    public:
        tcp_socket()
        {
            _initialize_platform();
        }

        tcp_socket(internal_socket s) { _socket = s; }

        ~tcp_socket()
        {
            if (!is_valid()) return;

            int r = closesocket(_socket);
            if (r == SOCKET_ERROR) log_wsa_error("~tcp_socket()");
        }

        bool is_valid() const { return _socket != invalid_socket; }

        tcp_socket(const tcp_socket&) = delete;
        tcp_socket& operator=(const tcp_socket&) = delete;

        tcp_socket(tcp_socket&& other) noexcept
            : _socket(other._socket)
        {
            other._socket = invalid_socket;
        }

        tcp_socket& operator=(tcp_socket&& other) noexcept
        {
            if (this != &other)
            {
                _socket = other._socket;
                other._socket = invalid_socket;
            }
            return *this;
        }

        bool create(
            const address_family af = address_family::ipv4)
        {
            _socket = socket(af, SOCK_STREAM, IPPROTO_TCP);
            if (!is_valid())
            {
                log_wsa_error("tcp_socket::create()");
                return false;
            }
            return true;
        }

        void make_invalid()
        {
            if (_socket != invalid_socket)
            {
                closesocket(_socket);
                _socket = invalid_socket;
            }
        }

        bool connect_ipv4(
             const std::string& host,
             const u_short port)
        {
            if (!is_valid()) return false;

            sockaddr_in local_addr{};
            local_addr.sin_family = AF_INET;
            local_addr.sin_port = htons(port);
            local_addr.sin_addr.s_addr = inet_addr(host.c_str());

            return ::connect(
                _socket,
                reinterpret_cast<sockaddr *>(&local_addr),
                sizeof(local_addr)) == 0;
        }

        bool bind_ipv4(const u_short port)
        {
            return bind_ipv4("0.0.0.0", port);
        }

        bool bind_ipv4(
            const std::string& host,
            const u_short port)
        {
            if (!is_valid()) return false;

            sockaddr_in local_addr{};
            local_addr.sin_family = AF_INET;
            local_addr.sin_port = htons(port);
            local_addr.sin_addr.s_addr = inet_addr(host.c_str());

            return (::bind(_socket, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) >= 0);
        }

        bool listen(const int backlog = 1)
        {
            return ::listen(_socket, backlog) >= 0;
        }

        tcp_socket accept()
        {
            sockaddr_storage client_addr{};
            int len = sizeof(client_addr);
            const internal_socket client_fd = ::accept(_socket, reinterpret_cast<sockaddr*>(&client_addr), &len);
            if (client_fd == invalid_socket)
                return{ tcp_socket{} };

            return tcp_socket{client_fd};
        }

        int send(const void* data, const size_t len, int msg = 0)
        {
            const int n = ::send(_socket, static_cast<const char*>(data), static_cast<int>(len), msg);
            return n;
        }

        int recv(void* buffer, const size_t len, int msg = 0)
        {
            const int n = ::recv(_socket, static_cast<char*>(buffer), static_cast<int>(len), msg);
            return n;
        }

        bool set_blocking(bool blocking = false)
        {
            if (!is_valid()) return false;
            unsigned long mode = blocking ? 0 : 1;
            return (ioctlsocket(_socket, FIONBIO, &mode) == 0);
        }

        bool set_reuse_address(const bool enable = true)
        {
            int opt = enable ? 1 : 0;
            return setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) == 0;
        }

        int close()
        {
            int value = -1;
            if (is_valid()) { value = _close_socket(_socket); }
            _socket = invalid_socket;
            return value;
        }

        connection_info get_peer_info() const
        {
            if (!is_valid())
                return {};

            sockaddr_storage addr{};
            socklen_t addr_len = sizeof(addr);

            if (getpeername(_socket, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0)
                return {};

            connection_info info;
            if (!_extract_info_from_addr(addr, info)) return {};

            return info;
        }

        connection_info get_local_info() const
        {
            if (!is_valid())
                return {};

            sockaddr_storage addr{};
            socklen_t addr_len = sizeof(addr);

            if (getsockname(_socket, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0)
                return {};

            connection_info info;
            if (!_extract_info_from_addr(addr, info)) return {};

            return info;
        }

    private:
        internal_socket _socket = invalid_socket;

        static int _close_socket(internal_socket s)
        {
            return closesocket(s);
        }

        static bool _extract_info_from_addr(
            const sockaddr_storage& addr,
            connection_info& info)
        {
            if (addr.ss_family == AF_INET)
            {
                const auto* addr_in = reinterpret_cast<const sockaddr_in*>(&addr);
                info.port = ntohs(addr_in->sin_port);

                char ip_str[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, sizeof(ip_str)))
                    return false;

                info.ip_address = ip_str;
                info.address_family = address_family::ipv4;
                return true;
            }
            else if (addr.ss_family == AF_INET6)
            {
                const auto* addr_in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
                info.port = ntohs(addr_in6->sin6_port);

                char ip_str[INET6_ADDRSTRLEN];
                if (!inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, sizeof(ip_str)))
                    return false;

                info.ip_address = ip_str;
                info.address_family = address_family::ipv6;
                return true;
            }

            return false;
        }

        static void _initialize_platform()
        {
            static std::atomic<bool> wsa_initialized = false;
            if ( !wsa_initialized )
            {
                wsa_initialized = true;
                WSADATA wsa_data;
                if ( WSAStartup( MAKEWORD(2, 2), &wsa_data ) != 0 )
                {
                    wsa_initialized = false;
                }
            }
        }
    };

    enum class request_result : uint8_t
    {
        ok,
        graceful_close,
        error
    };

    inline request_result flush_buffer(
        core::tcp_socket& socket,
        std::vector<uint8_t>& buffer)
    {
        if (buffer.empty()) return request_result::ok;

        const int r = socket.send(
            buffer.data(),
            buffer.size());

        if (r < 0)
        {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK)
                return request_result::ok;

            if (err == 0) return request_result::ok;

            return request_result::error;
        }

        buffer.erase(buffer.begin(), buffer.begin() + r);

        return request_result::ok;
    }

    inline request_result update_receive(
        core::tcp_socket& socket,
        std::vector<uint8_t>& buffer)
    {
        uint8_t local[4096];
        const int r =
            socket.recv(local, sizeof(local));

        if (r == 0) return request_result::graceful_close;
        if (r < 0)
        {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK)
                return request_result::ok;

            if (err == 0) return request_result::ok;

            return request_result::error;
        }

        buffer.insert(buffer.end(), local, local + r);

        return request_result::ok;
    }
}

namespace win_tcp
{
    class single_client_server
    {
    public:
        single_client_server() = default;
        ~single_client_server() = default;

        single_client_server(const single_client_server&) = delete;
        single_client_server& operator=(const single_client_server&) = delete;

        single_client_server(single_client_server&&) = delete;
        single_client_server& operator=(single_client_server&&) = delete;

        explicit single_client_server(
            const uint16_t port)
        {
            if (!_acceptor.create()) return;
            if (!_acceptor.set_reuse_address()) return;
            if (!_acceptor.bind_ipv4(port)) return;
            if (!_acceptor.listen(1024)) return;
            if (!_acceptor.set_blocking(false)) return;
        }

        bool is_valid() const
        {
            return _acceptor.is_valid();
        }

        bool has_client() const
        {
            return _only_client.is_valid();
        }

        // return: could accept client.
        bool accept_client()
        {
            if (_only_client.is_valid()) return false;

            core::tcp_socket s = _acceptor.accept();

            if (!s.is_valid())          return false;
            if (!s.set_blocking(false)) return false;

            _only_client = std::move(s);
            return true;
        }

        enum class tick_client_return
        {
            ok,
            client_error,
            client_disconnected
        };

        tick_client_return tick_client()
        {
            auto r = _tick_client();

            if (r != tick_client_return::ok)
                close_client();

            return r;
        }

        bool close_client()
        {
            out_buffer.clear();
            in_buffer.clear();
            _only_client.close();
            return true;
        }

        const core::tcp_socket& get_host() const { return _acceptor; }
        const core::tcp_socket& get_client() const { return _only_client; }

        std::vector<uint8_t>& get_out_buffer() { return out_buffer; }
        std::vector<uint8_t>& get_in_buffer() { return in_buffer; }

    private:
        core::tcp_socket _acceptor{};

        core::tcp_socket _only_client{};
        std::vector<uint8_t> out_buffer{};
        std::vector<uint8_t> in_buffer{};

        tick_client_return _tick_client()
        {
            if (!_only_client.is_valid())
                return tick_client_return::client_error;

            auto r = core::update_receive(
                _only_client,
                in_buffer);

            if (r == core::request_result::error)
                return tick_client_return::client_error;

            if (r == core::request_result::graceful_close)
                return tick_client_return::client_disconnected;

            r = core::flush_buffer(
                _only_client,
                out_buffer);

            if (r == core::request_result::error)
                return tick_client_return::client_error;

            return tick_client_return::ok;
        }
    };
}

#endif //WIN_TCP_WIN_TCP_HPP