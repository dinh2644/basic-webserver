#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h> // For gethostbyname
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
// #include <filesystem> // Not needed here
#include <thread>
#include <csignal>
#include <atomic>
#include <signal.h>
#include <vector>
#include <mutex>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <ctime>

// --- Globals ---
int proxyServerSd; // listening socket for proxy
std::atomic<bool> serverRunning(true);
std::vector<std::thread> threads;
std::mutex threadMutex; // protects 'threads' vector

// For Tracking Client Sockets (connections from browser/client)
std::vector<int> clientSockets;
std::mutex clientSocketsMutex; // protects 'clientSockets' vector

// Target Web Server Info (to be set from argv)
std::string targetWebServerHost;
int targetWebServerPort;
// --- End Globals ---

/*
 *********************************************************** Helpers ***********************************************************
 */

void removeClientSocket(int sd); // forward declaration

// RAII for client socket descriptor (browser <-> proxy)
struct ClientSocketCloser
{
    int sd;
    bool managed;

    ClientSocketCloser(int socket_descriptor) : sd(socket_descriptor), managed(true) {}
    ClientSocketCloser(const ClientSocketCloser &) = delete;
    ClientSocketCloser &operator=(const ClientSocketCloser &) = delete;
    ClientSocketCloser(ClientSocketCloser &&other) noexcept : sd(other.sd), managed(other.managed)
    {
        other.managed = false;
        other.sd = -1;
    }
    ClientSocketCloser &operator=(ClientSocketCloser &&other) noexcept
    {
        if (this != &other)
        {
            if (managed && sd >= 0)
            {
                close(sd);
                removeClientSocket(sd);
            }
            sd = other.sd;
            managed = other.managed;
            other.managed = false;
            other.sd = -1;
        }
        return *this;
    }
    ~ClientSocketCloser()
    {
        if (managed && sd >= 0)
        {
            // std::cout << "[Proxy ~ClientSocketCloser] Closing client socket: " << sd << std::endl; // debug
            close(sd);
            removeClientSocket(sd);
        }
    }
};

// Helper to remove client socket descriptor safely
void removeClientSocket(int sd)
{
    std::lock_guard<std::mutex> lock(clientSocketsMutex);
    // std::cout << "[Proxy] Attempting to remove client socket: " << sd << std::endl; // debug
    clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), sd), clientSockets.end());
}

// Function to get current timestamp string
std::string getCurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Signal handler for graceful shutdown
void signalHandler(int signum)
{
    std::cout << "\n[" << std::this_thread::get_id() << "] ProxyServer Signal " << signum << " received. Shutting down proxy safely...\n";
    serverRunning = false;

    // Unblock accept() - assumes proxy listens on port from argv[1]
    // Needs proxyPort available, or hardcode like below if known
    int proxyPort = 28000; // Assuming default/known proxy port for dummy connection
    int dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (dummy_sock >= 0)
    {
        sockaddr_in selfAddr;
        bzero((char *)&selfAddr, sizeof(selfAddr));
        selfAddr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &selfAddr.sin_addr);
        selfAddr.sin_port = htons(proxyPort); // <<< MUST MATCH PROXY LISTENING PORT
        int flags = fcntl(dummy_sock, F_GETFL, 0);
        fcntl(dummy_sock, F_SETFL, flags | O_NONBLOCK);
        connect(dummy_sock, (struct sockaddr *)&selfAddr, sizeof(selfAddr));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        close(dummy_sock);
    }

    // Shutdown active client connections (browser <-> proxy)
    std::cout << "[ProxyServer] Shutting down active client connections...\n";
    {
        std::lock_guard<std::mutex> lock(clientSocketsMutex);
        for (int clientSd : clientSockets)
        {
            // std::cout << "[ProxyServer] Shutting down client SD: " << clientSd << std::endl; // debug
            if (shutdown(clientSd, SHUT_RDWR) < 0)
            { /* handle error if needed */
            }
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Join all active threads
    std::cout << "[ProxyServer] Waiting for active worker threads to complete...\n";
    {
        std::lock_guard<std::mutex> lock(threadMutex);
        for (auto &t : threads)
        {
            if (t.joinable())
            {
                t.join();
            }
        }
        threads.clear();
    }

    std::cout << "[ProxyServer] Closing proxy listener socket...\n";
    if (proxyServerSd >= 0)
    {
        close(proxyServerSd);
    }
    std::cout << "[ProxyServer] -- Proxy shutdown complete --" << std::endl;
    exit(0);
}

/*
 *********************************************************** handleProxyRequest ***********************************************************
 */
void handleProxyRequest(int clientSd) // handle request from browser/client
{
    // RAII for the client socket (browser <-> proxy)
    ClientSocketCloser client_socket_closer(clientSd);

    // std::cout << "[" << std::this_thread::get_id() << "] Proxy handling client connection on socket " << clientSd << "\n"; // debug

    // 1. Receive client request
    const int buffer_size = 8192; // increased buffer size
    char requestBuffer[buffer_size] = {0};
    ssize_t bytes_received = recv(clientSd, requestBuffer, buffer_size - 1, MSG_NOSIGNAL);

    if (bytes_received <= 0)
    {
        // std::cout << "[" << std::this_thread::get_id() << "] Proxy: Client disconnected or recv error on socket " << clientSd << "\n"; // debug
        return; // client_socket_closer handles cleanup
    }
    requestBuffer[bytes_received] = '\0';
    std::string clientRequest(requestBuffer, bytes_received); // store full request

    // 2. Parse request (optional, but good for logging/understanding)
    // std::string method, request_uri, http_version;
    // try {
    //     std::istringstream request_stream(clientRequest);
    //     std::string request_line;
    //     getline(request_stream, request_line);
    //     std::istringstream request_line_stream(request_line);
    //     request_line_stream >> method >> request_uri >> http_version;
    // } catch (...) {
    //     std::cerr << "[" << std::this_thread::get_id() << "] Proxy: Error parsing request line from client " << clientSd << std::endl; // debug
    //     // Consider sending 400 Bad Request?
    //     return;
    // }

    // 3. Connect to the target web server
    int serverConnectionSd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverConnectionSd < 0)
    {
        perror("[Proxy] Failed to create socket for web server connection");
        // Consider sending 502 Bad Gateway to client?
        return;
    }

    struct hostent *serverHost = gethostbyname(targetWebServerHost.c_str());
    if (!serverHost)
    {
        std::cerr << "[Proxy] Failed to resolve target web server hostname: " << targetWebServerHost << std::endl;
        close(serverConnectionSd);
        // Consider sending 502 Bad Gateway to client?
        return;
    }

    sockaddr_in serverAddr;
    bzero((char *)&serverAddr, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    bcopy((char *)serverHost->h_addr, (char *)&serverAddr.sin_addr.s_addr, serverHost->h_length);
    serverAddr.sin_port = htons(targetWebServerPort);

    if (connect(serverConnectionSd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        perror("[Proxy] Failed to connect to target web server");
        close(serverConnectionSd);
        // Consider sending 502 Bad Gateway to client?
        return;
    }
    // RAII for server connection socket
    ClientSocketCloser server_socket_closer(serverConnectionSd); // use the same RAII class

    // 4. Forward client request to web server
    ssize_t bytes_sent = send(serverConnectionSd, clientRequest.c_str(), clientRequest.length(), MSG_NOSIGNAL);
    if (bytes_sent < 0 || (size_t)bytes_sent != clientRequest.length())
    {
        perror("[Proxy] Failed to send full request to target web server");
        // server_socket_closer and client_socket_closer handle cleanup
        return;
    }

    // 5. Log: Forwarding request to server
    std::cout << "proxy-forward, server, "
              << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;

    // 6. Receive response from web server and forward to client (Streaming)
    char responseBuffer[buffer_size] = {0};
    ssize_t response_bytes_received;
    bool first_chunk = true;

    while ((response_bytes_received = recv(serverConnectionSd, responseBuffer, buffer_size, MSG_NOSIGNAL)) > 0)
    {
        // 7. Log: Forwarding response to client (only log once per response cycle)
        if (first_chunk)
        {
            std::cout << "proxy-forward, client, "
                      << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
            first_chunk = false;
        }

        // 8. Forward chunk to client
        ssize_t chunk_bytes_sent = send(clientSd, responseBuffer, response_bytes_received, MSG_NOSIGNAL);
        if (chunk_bytes_sent < 0 || chunk_bytes_sent != response_bytes_received)
        {
            perror("[Proxy] Failed to send full response chunk to client");
            // Error sending to client, stop forwarding
            break;
        }
        // Consider adding a check for !serverRunning here if transfers are very long
        if (!serverRunning)
            break;
    }

    if (response_bytes_received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
        perror("[Proxy] Error receiving response from target web server");
    }

    // 9. Connections are closed automatically by RAII destructors
    // (~SocketCloser for serverConnectionSd, ~ClientSocketCloser for clientSd)
    // std::cout << "[" << std::this_thread::get_id() << "] Proxy finished handling client " << clientSd << "\n"; // debug
}

/*
 *********************************************************** Main (Proxy Server) ***********************************************************
 */
int main(int argc, char *argv[])
{
    // Expect proxy port, target server host, target server port
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <proxy_listen_port> <target_server_host> <target_server_port>" << std::endl;
        exit(1);
    }

    int proxyPort = atoi(argv[1]);
    targetWebServerHost = argv[2];       // store globally
    targetWebServerPort = atoi(argv[3]); // store globally

    if (proxyPort <= 0 || proxyPort > 65535 || targetWebServerPort <= 0 || targetWebServerPort > 65535)
    {
        std::cerr << "Invalid port number provided." << std::endl;
        exit(1);
    }

    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN); // ignore sigpipe, check send/recv errors instead

    // Setup proxy listening socket
    sockaddr_in proxyAddr;
    bzero((char *)&proxyAddr, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxyAddr.sin_port = htons(proxyPort);

    proxyServerSd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxyServerSd < 0)
    {
        perror("[ProxyServer] Error establishing proxy server socket");
        exit(1);
    }

    int option = 1;
    if (setsockopt(proxyServerSd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
    {
        perror("[ProxyServer] setsockopt(SO_REUSEADDR) failed");
        close(proxyServerSd);
        exit(1);
    }

    if (bind(proxyServerSd, (struct sockaddr *)&proxyAddr, sizeof(proxyAddr)) < 0)
    {
        perror("[ProxyServer] Error binding proxy socket");
        close(proxyServerSd);
        exit(1);
    }

    if (listen(proxyServerSd, SOMAXCONN) < 0)
    {
        perror("[ProxyServer] Error listening on proxy socket");
        close(proxyServerSd);
        exit(1);
    }

    std::cout << "[ProxyServer] Listening on port " << proxyPort
              << ", forwarding to " << targetWebServerHost << ":" << targetWebServerPort
              << ". Press Ctrl+C to shut down.\n";

    // Main accept loop
    while (serverRunning)
    {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int newClientSd = accept(proxyServerSd, (sockaddr *)&clientAddr, &clientAddrSize);

        if (!serverRunning)
        {
            if (newClientSd >= 0)
                close(newClientSd);
            break;
        }

        if (newClientSd < 0)
        {
            if (errno == EINTR && !serverRunning)
                break;
            else if (errno != EINTR)
            {
                perror("[ProxyServer] Error accepting client connection");
            }
            continue;
        }

        // Connection accepted from client
        try
        {
            { // add client socket to tracking list
                std::lock_guard<std::mutex> lock(clientSocketsMutex);
                clientSockets.push_back(newClientSd);
                // std::cout << "[ProxyServer] Added client socket " << newClientSd << " to tracking list." << std::endl; // debug
            }

            // Create and manage worker thread for proxy logic
            std::thread workerThread(handleProxyRequest, newClientSd);
            { // add thread handle to tracking list
                std::lock_guard<std::mutex> lock(threadMutex);
                threads.push_back(std::move(workerThread));
                // std::cout << "[ProxyServer] Launched thread " << threads.back().get_id() << " for client socket " << newClientSd << std::endl; // debug
            }
        }
        catch (const std::system_error &e)
        {
            std::cerr << "[ProxyServer] Error creating thread: " << e.what() << " (" << e.code() << ")" << '\n';
            removeClientSocket(newClientSd);
            close(newClientSd);
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ProxyServer] Exception during connection handling setup: " << e.what() << '\n';
            removeClientSocket(newClientSd);
            close(newClientSd);
        }
    } // end while(serverRunning)

    std::cout << "[ProxyServer] Server loop finished." << std::endl;
    return 0;
}