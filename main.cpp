#include <chrono>
#include <iostream>
#include <thread>

#include "win_tcp.hpp"

int main()
{
    win_tcp::single_client_server s(7070);
    if (!s.is_valid())
    {
        std::cerr << "server is invalid" << std::endl;
        return 1;
    }
    std::cout << "CONNECTED ON: " << s.get_host().get_local_info().to_string() << std::endl;

    uint8_t heart_rate_value = 62;

    while (true)
    {
        if (!s.has_client())
        {
            if (s.accept_client())
                std::cout << "ACCEPTED NEW CLIENT FROM: " << s.get_client().get_peer_info().to_string() << std::endl;
        }

        if (s.has_client())
        {
            s.get_out_buffer().clear();
            s.get_out_buffer().push_back(heart_rate_value);

            const auto r = s.tick_client();
            s.get_in_buffer().clear();

            if (r == win_tcp::single_client_server::tick_client_return::client_disconnected ||
                r == win_tcp::single_client_server::tick_client_return::client_error)
                std::cout << "CLIENT DISCONNECTED" << std::endl;

        }

        std::this_thread::yield();
    }

    return 0;
}
