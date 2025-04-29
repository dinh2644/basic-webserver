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
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <filesystem>
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
#include <netdb.h>

// Globals
int serverSd;
std::atomic<bool> serverRunning(true);
std::vector<std::thread> threads;
std::mutex threadMutex;

// For Tracking Client Sockets
std::vector<int> clientSockets;
std::mutex clientSocketsMutex;

// Target web server Info (to be set from argv)
std::string targetAddr;
int targetPort;

/*
 *********************************************************** Helpers ***********************************************************
 */

void removeClientSocket(int sd)
{
    std::lock_guard<std::mutex> lock(clientSocketsMutex);
    clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), sd), clientSockets.end());
}

// RAII for socket descriptor
struct SocketCloser
{
    int sd;
    bool managed;

    SocketCloser(int socket_descriptor) : sd(socket_descriptor), managed(true) {} // Main constructor
    // Disable copy construction & copy assignment (can't have multiple objects dealing with the same socket)
    SocketCloser(const SocketCloser &) = delete;
    SocketCloser &operator=(const SocketCloser &) = delete;
    // Move constructor (accepts an rvalue reference to another SocketCloser object)
    // allows moving (w/o copying) e.g. SocketCloser some_var = SocketCloser(serverSd);
    SocketCloser(SocketCloser &&other) noexcept : sd(other.sd), managed(other.managed)
    {
        other.managed = false;
        other.sd = -1;
    }
    // Move operator
    SocketCloser &operator=(SocketCloser &&other) noexcept
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
    // Destructor
    ~SocketCloser()
    {
        if (managed && sd >= 0)
        {
            // std::cout << "[Proxy ~SocketCloser] Closing client socket: " << sd << std::endl; // debugging
            close(sd);
            removeClientSocket(sd);
        }
    }
};

std::string getCurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void signalHandler(int signum)
{
    std::cout << "\n[" << std::this_thread::get_id() << "] Web Server Signal " << signum << " received. Shutting down server safely...\n";
    serverRunning = false;

    // Shutdown active client connections
    std::cout << "[WebServer] Shutting down active client connections...\n";
    {
        std::lock_guard<std::mutex> lock(clientSocketsMutex);
        for (int sd : clientSockets)
        {
            std::cout << "Shutting down SD: " << sd << std::endl; // debugging
            if (shutdown(sd, SHUT_RDWR) < 0)                      // SHUT_RDWR = No more receptions or transmissions.
            {
                // Only print perror if it wasn't expected (e.g., socket already closed)
                if (errno != ENOTCONN && errno != EPIPE)
                {
                    perror("[WebServer] shutdown error");
                }
            }
        }
    }
    // Give threads a moment to react to socket shutdown/errors
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Join all active threads before shutdown
    std::cout << "[WebServer] Waiting for active worker threads to complete...\n";
    {
        std::lock_guard<std::mutex> lock(threadMutex);
        std::cout << "[WebServer] Joining " << threads.size() << " threads.\n"; // debugging

        for (auto &t : threads)
        {
            if (t.joinable())
            {
                std::cout << "Joining thread " << t.get_id() << std::endl; // debugging
                t.join();
                std::cout << "Joined thread " << t.get_id() << std::endl; // debugging
            }
            // else
            // {
            //     std::cout << "Thread " << t.get_id() << " not joinable.\n"; // debugging
            // }
        }
        threads.clear();
        std::cout << "Threads vector cleared.\n"; // debugging
    }

    std::cout << "[WebServer] Closing server listener socket...\n";
    if (serverSd >= 0)
    {
        close(serverSd);
    }
    std::cout << "[WebServer] -- Proxy server shutdown complete --" << std::endl;
    exit(0);
}

/*
 *********************************************************** handleProxyRequest ***********************************************************
 */
void handleProxyRequest(int clientSd)
{
    // RAII for socket descriptor
    SocketCloser client_socket_closer(clientSd);

    // std::cout << "[" << std::this_thread::get_id() << "] Proxy handling client connection on socket " << clientSd << "\n"; // debugging

    // Retrieve http request msg
    const int buffer_size = 8192;
    char requestBuffer[buffer_size] = {0};
    ssize_t bytes_received = recv(clientSd, requestBuffer, buffer_size - 1, MSG_NOSIGNAL);
    if (bytes_received <= 0)
    {
        // std::cout << "[" << std::this_thread::get_id() << "] Proxy: Client disconnected or recv error on socket " << clientSd << "\n"; // debugging
        return; // client_socket_closer handles cleanup
    }
    requestBuffer[bytes_received] = '\0';
    std::string clientRequest(requestBuffer, bytes_received); // store full request

    // std::string method, request_uri, http_version;
    // try {
    //     std::istringstream request_stream(clientRequest);
    //     std::string request_line;
    //     getline(request_stream, request_line);
    //     std::istringstream request_line_stream(request_line);
    //     request_line_stream >> method >> request_uri >> http_version;
    // } catch (...) {
    //     std::cerr << "[" << std::this_thread::get_id() << "] Proxy: Error parsing request line from client " << clientSd << std::endl; // debugging
    //     return;
    // }

    // Connect to the target web server
    int serverTargetSd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverTargetSd < 0)
    {
        perror("[Proxy] Failed to create socket for web server connection");
        return;
    }

    struct hostent *serverHost = gethostbyname(targetAddr.c_str());
    if (!serverHost)
    {
        std::cerr << "[Proxy] Failed to resolve target web server hostname: " << targetAddr << std::endl;
        close(serverTargetSd);
        return;
    }

    // Setup socket for target web server
    sockaddr_in servAddr;
    bzero((char *)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(targetPort);

    if (connect(serverTargetSd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        perror("[Proxy] Failed to connect to target web server");
        close(serverTargetSd);
        return;
    }
    // RAII for target server connection socket
    SocketCloser server_socket_closer(serverTargetSd);

    // Forward client request to web server
    ssize_t bytes_sent = send(serverTargetSd, clientRequest.c_str(), clientRequest.length(), MSG_NOSIGNAL);
    if (bytes_sent < 0 || (size_t)bytes_sent != clientRequest.length())
    {
        perror("[Proxy] Failed to send full request to target web server");
        return;
    }

    // Log forwarding request to server
    std::cout << "proxy-forward, server, " << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;

    // Receive response from web server & forward to client
    char responseBuffer[buffer_size] = {0};
    ssize_t response_bytes_received;
    bool first_chunk = true;

    while ((response_bytes_received = recv(serverTargetSd, responseBuffer, buffer_size, MSG_NOSIGNAL)) > 0)
    {
        // Log forwarding response to client (only log once per response cycle)
        if (first_chunk)
        {
            std::cout << "proxy-forward, client, " << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
            first_chunk = false;
        }

        // Forward chunk to client
        ssize_t chunk_bytes_sent = send(clientSd, responseBuffer, response_bytes_received, MSG_NOSIGNAL);
        if (chunk_bytes_sent < 0 || chunk_bytes_sent != response_bytes_received)
        {
            perror("[Proxy] Failed to send full response chunk to client");
            break; // error sending to client, stop forwarding
        }
        if (!serverRunning) // incase transfer takes too long
            break;
    }

    if (response_bytes_received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
        perror("[Proxy] Error receiving response from target web server");
    }

    // std::cout << "[" << std::this_thread::get_id() << "] Proxy finished handling client " << clientSd << "\n"; // debugging
}

/*
 *********************************************************** Main (Proxy Server) ***********************************************************
 */
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <proxy_listen_port> <target_server_host> <target_server_port>" << std::endl;
        exit(1);
    }

    int proxyPort = atoi(argv[1]);
    targetAddr = argv[2];
    targetPort = atoi(argv[3]);

    if (proxyPort <= 0 || proxyPort > 65535 || targetPort <= 0 || targetPort > 65535)
    {
        std::cerr << "Invalid port number provided." << std::endl;
        exit(1);
    }

    // Setup signal handlers
    signal(SIGINT, signalHandler);  // 2
    signal(SIGTERM, signalHandler); // 15
    signal(SIGPIPE, SIG_IGN);       // ignore sigpipe, check send/recv errors instead

    // Setup socket
    sockaddr_in proxyAddr;
    bzero((char *)&proxyAddr, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxyAddr.sin_port = htons(proxyPort);

    // Open stream oriented socket with internet address
    // Also keep track of the socket descriptor
    serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSd < 0)
    {
        perror("[ProxyServer] Error establishing proxy server socket");
        exit(1);
    }

    int option = 1;
    if (setsockopt(serverSd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
    {
        perror("[ProxyServer] setsockopt(SO_REUSEADDR) failed");
        close(serverSd);
        exit(1);
    }

    // Bind socket (to its local address)
    if (bind(serverSd, (struct sockaddr *)&proxyAddr, sizeof(proxyAddr)) < 0)
    {
        perror("[ProxyServer] Error binding proxy socket");
        close(serverSd);
        exit(1);
    }

    // SOMAXCONN defines the maximum number allowed to pass to listen() per system
    // listen for up to SOMAXCONN requests at a time
    if (listen(serverSd, SOMAXCONN) < 0)
    {
        perror("[ProxyServer] Error listening on proxy socket");
        close(serverSd);
        exit(1);
    }

    std::cout << "[ProxyServer] Listening on port " << proxyPort
              << ", forwarding to " << targetAddr << ":" << targetPort
              << ". Press Ctrl+C to shut down.\n";

    while (serverRunning)
    {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int newClientSd = accept(serverSd, (sockaddr *)&clientAddr, &clientAddrSize);

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
                continue;
            }
            std::cout << "accept() interrupted but server still running (errno=" << errno << ")" << std::endl; // debugging
            continue;
        }

        // Connection accepted
        try
        {
            // Add client socket to tracking list
            {
                std::lock_guard<std::mutex> lock(clientSocketsMutex);
                clientSockets.push_back(newClientSd);
                // std::cout << "[ProxyServer] Added client socket " << newClientSd << " to tracking list." << std::endl; // debugging
            }

            // Create and manage worker thread
            std::thread workerThread(handleProxyRequest, newClientSd);
            {
                std::lock_guard<std::mutex> lock(threadMutex);
                threads.push_back(std::move(workerThread));
                // std::cout << "[ProxyServer] Launched thread " << threads.back().get_id() << " for client socket " << newClientSd << std::endl; // debugging
            }
        }
        catch (const std::system_error &e)
        {
            std::cerr << "[ProxyServer] Error creating thread: " << e.what() << " (" << e.code() << ")" << '\n';
            removeClientSocket(newClientSd);
            close(newClientSd);
        }
    }

    std::cout << "[ProxyServer] Server loop finished." << std::endl;
    return 0;
}