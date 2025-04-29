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

// Globals
int serverSd;
std::atomic<bool>
    serverRunning(true);
std::vector<std::thread> threads;
std::mutex threadMutex;

// For Tracking Client Sockets
std::vector<int> clientSockets;
std::mutex clientSocketsMutex;

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
    std::cout << "[WebServer] -- Web server shutdown complete --" << std::endl;
    exit(0);
}

inline bool fileExists(const std::string &fileName)
{
    struct stat requestBuffer;
    return (stat(fileName.c_str(), &requestBuffer) == 0);
}

/*
 *********************************************************** handleRequest ***********************************************************
 */
void handleRequest(int clientSd)
{
    // RAII for socket descriptor
    SocketCloser socket_closer(clientSd);

    // std::cout << "[" << std::this_thread::get_id() << "] Handling connection on socket " << clientSd << "\n"; // debugging
    std::string responseCodeStr = "500";

    // Retrieve http request msg
    const int buffer_size = 8192;
    char requestBuffer[buffer_size] = {0};
    ssize_t bytes_received = recv(socket_closer.sd, requestBuffer, buffer_size - 1, MSG_NOSIGNAL);
    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            // std::cout << "[" << std::this_thread::get_id() << "] Client disconnected socket " << socket_closer.sd << "\n"; // debugging
        }
        else
        {
            // perror("recv error");                                                                                    // debugging
            // std::cout << "[" << std::this_thread::get_id() << "] Recv error on socket " << socket_closer.sd << "\n"; // debugging
        }
        return;
    }
    requestBuffer[bytes_received] = '\0';

    // Parse http request msg
    std::string request(requestBuffer);
    std::istringstream request_stream(request);
    std::string request_line;
    getline(request_stream, request_line); // read only the first line

    // Extract "/<SOME_FILE>.extension"
    std::istringstream request_line_stream(request_line);
    std::string method, request_uri, http_version;
    request_line_stream >> method >> request_uri >> http_version;

    if (method != "GET")
    {
        std::string badReqMsg = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        responseCodeStr = "405";
        std::cout << "server-response, " << responseCodeStr << ", "
                  << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
        send(socket_closer.sd, badReqMsg.c_str(), badReqMsg.length(), MSG_NOSIGNAL);
        return;
    }

    std::string file_path = request_uri.substr(1);

    // Handle invalid path (also prevent directory traversal)
    if (file_path.empty() || file_path.find("..") != std::string::npos)
    {
        std::string notFoundMsg = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: 153\r\n\r\n";
        std::string html404Body = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource could not be found on this server.</p></body></html>";
        notFoundMsg += html404Body;
        responseCodeStr = "404";
        std::cout << "server-response, " << responseCodeStr << ", "
                  << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
        send(socket_closer.sd, notFoundMsg.c_str(), notFoundMsg.length(), MSG_NOSIGNAL);
        // std::cout << "[WebServer] Directory traversal attempt blocked: " << request_uri << std::endl; // debugging
        return;
    }

    // Extension check
    auto ends_with = [](const std::string &value, const std::string &ending)
    {
        if (ending.size() > value.size())
            return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    };

    bool isHTML = ends_with(file_path, ".html");
    bool isJPEG = ends_with(file_path, ".jpg") || ends_with(file_path, ".jpeg");
    bool isPDF = ends_with(file_path, ".pdf");
    std::string contentType;

    if (isHTML)
        contentType = "text/html; charset=utf-8";
    else if (isJPEG)
        contentType = "image/jpeg";
    else if (isPDF)
        contentType = "application/pdf";
    else
    {
        // Unsupported media type or treat as not found
        std::string notFoundMsg = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: 153\r\n\r\n";
        std::string html404Body = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource could not be found on this server.</p></body></html>";
        notFoundMsg += html404Body;
        responseCodeStr = "404";
        std::cout << "server-response, " << responseCodeStr << ", "
                  << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
        send(socket_closer.sd, notFoundMsg.c_str(), notFoundMsg.length(), MSG_NOSIGNAL);
        // std::cout << "[WebServer] Unsupported file type requested: " << file_path << "\n"; // debugging
        return;
    }

    // Check in server if file exists
    if (!fileExists(file_path))
    {
        std::string notFoundMsg = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: 153\r\n\r\n";
        std::string html404Body = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource could not be found on this server.</p></body></html>";
        notFoundMsg += html404Body;
        responseCodeStr = "404";
        std::cout << "server-response, " << responseCodeStr << ", "
                  << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
        send(socket_closer.sd, notFoundMsg.c_str(), notFoundMsg.length(), MSG_NOSIGNAL);
        // std::cout << "[WebServer] File not found: " << file_path << "\n"; // debugging
        return;
    }

    // Send file content
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::string errorBody = "<html><head><title>500 Internal Server Error</title></head>"
                                "<body><h1>500 Internal Server Error</h1>"
                                "<p>The server encountered an unexpected condition that prevented it from fulfilling the request.</p>"
                                "<p>The file exists but could not be accessed.</p>"
                                "</body></html>";

        std::string errorMsg = "HTTP/1.1 500 Internal Server Error\r\n"
                               "Content-Type: text/html\r\n"
                               "Content-Length: " +
                               std::to_string(errorBody.length()) + "\r\n"
                                                                    "Connection: close\r\n\r\n" +
                               errorBody;

        responseCodeStr = "500";
        std::cout << "server-response, " << responseCodeStr << ", "
                  << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
        send(socket_closer.sd, errorMsg.c_str(), errorMsg.length(), MSG_NOSIGNAL);
        return;
    }

    std::streamsize fileSize = file.tellg(); // get file size
    file.seekg(0, std::ios::beg);            // seek back to beginning

    // Construct success headers
    responseCodeStr = "200";
    std::string successMsg = "HTTP/1.1 " + responseCodeStr + " OK\r\n";
    std::string headers = successMsg;
    headers += "Content-Type: " + contentType + "\r\n";
    headers += "Content-Length: " + std::to_string(fileSize) + "\r\n";
    headers += "Connection: close\r\n"; // tell proxy we will close connection
    headers += "\r\n";                  // http header separator

    // Log before sending headers
    std::cout << "server-response, " << responseCodeStr << ", " << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;

    // Send headers
    ssize_t sent_bytes = send(socket_closer.sd, headers.c_str(), headers.length(), MSG_NOSIGNAL);
    if (sent_bytes < 0 || (size_t)sent_bytes != headers.length())
    {
        // std::cerr << "Error sending headers for " << file_path << std::endl; // debugging
        return;
    }

    // Send body in chunks
    // (using this manual method to prevent allocating too much RAM for possibly large files w/ istreambuf_iterator)
    const size_t CHUNK_SIZE = 4096;
    char fileBuffer[CHUNK_SIZE];
    while (file.read(fileBuffer, CHUNK_SIZE) || file.gcount() > 0)
    {
        // Check if server is shutting down between chunks (optional, but good for very large files)
        if (!serverRunning)
        {
            // std::cerr << "Server shutting down during file transfer for " << file_path << "\n"; // debugging
            break; // Exit loop, SocketCloser will handle cleanup
        }

        ssize_t current_chunk_size = file.gcount();
        ssize_t chunk_sent_bytes = send(socket_closer.sd, fileBuffer, current_chunk_size, MSG_NOSIGNAL); // Use socket_closer.sd

        if (chunk_sent_bytes < 0)
        {
            // Error occurred (e.g. client disconnected, or shutdown() called from signal handler)
            // std::cerr << "Error sending file content chunk for " << file_path << " (socket: " << socket_closer.sd << ")" << "\n"; // debugging
            // perror("send error detail");                                                                                          // debugging
            break;
        }
        if ((size_t)chunk_sent_bytes != current_chunk_size)
        {
            // For simplicity, treat this section as an error condition and break. (this should rarely occur w/ blocking sockets error)
            // For future reference: handle trying to send remaining chunks?
            // std::cerr << "Warning: Sent fewer bytes than expected for chunk: " << chunk_sent_bytes << "/" << current_chunk_size << "\n"; // debugging
            break;
        }
    }
    file.close();
    // std::cout << "[" << std::this_thread::get_id() << "] Response sent for: " << file_path << " on socket " << socket_closer.sd << "\n"; // debugging
}

/*
 *********************************************************** Main ***********************************************************
 */

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <web_server_port>" << std::endl;
        exit(1);
    }
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535)
    {
        std::cerr << "Invalid port number: " << argv[1] << std::endl;
        exit(1);
    }

    // Setup signal handler
    signal(SIGINT, signalHandler);  // 2
    signal(SIGTERM, signalHandler); // 15

    // Setup socket
    sockaddr_in servAddr;
    bzero((char *)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    // Open stream oriented socket with internet address
    // Also keep track of the socket descriptor
    serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSd < 0)
    {
        perror("Error establishing the server socket");
        exit(1);
    }

    // Set socket options
    int option = 1;
    if (setsockopt(serverSd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
    {
        perror("[WebServer] setsockopt(SO_REUSEADDR) failed");
        close(serverSd);
        exit(1);
    }

    // Bind socket (to its local address)
    if (bind(serverSd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        perror("[WebServer] Error binding socket");
        close(serverSd);
        exit(1);
    }

    std::cout << "Waiting for a client to connect..." << "\n";

    // SOMAXCONN defines the maximum number allowed to pass to listen() per system
    // listen for up to SOMAXCONN requests at a time
    if (listen(serverSd, SOMAXCONN) < 0)
    {
        perror("[WebServer] Error listening on socket");
        close(serverSd);
        exit(1);
    }

    std::cout << "[WebServer] Listening on port " << port << ". Press Ctrl+C to shut down." << "\n";

    while (serverRunning)
    {
        // Receive a request from client server using accept
        // We need a new address to connect with the client
        sockaddr_in newSockAddr;
        socklen_t newSockAddrSize = sizeof(newSockAddr);
        // Accept, create a new socket descriptor to
        // Handle the new connection with client
        int clientSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);

        if (!serverRunning) // check flag immediately after accept returns
        {
            if (clientSd >= 0)
                close(clientSd); // close newly accepted socket if shutting down
            break;               // exit loop if serverRunning is false
        }

        if (clientSd < 0) // handle accept errors
        {
            // EINTR means accept was interrupted by our signal (okay if shutting down)
            if (errno == EINTR && !serverRunning)
            {
                // std::cout << "accept() interrupted gracefully during shutdown." << std::endl; // debugging
                break;
            }
            else if (errno != EINTR) // log other errors if not shutting down
            {
                perror("[WebServer] Error accepting client connection request");
                // For future reference:
                // decide if error is fatal. for errors like (e.g. EMFILE, ENFILE),
                // it might be better to pause and retry rather than exit
                // for simplicity now, th are using continue to try accept next connection
                // test later for errors like EMFILE if it happens frequently by adding a small sleep here
                // std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            // If errno == EINTR but serverRunning is still true, it was interrupted by something else.
            // Just continue the loop.
            std::cout << "accept() interrupted but server still running (errno=" << errno << ")" << std::endl; // debugging
            continue;
        }

        // Connection accepted
        try
        {
            // Add client socket to tracking list
            {
                std::lock_guard<std::mutex> lock(clientSocketsMutex);
                clientSockets.push_back(clientSd);
                // std::cout << "[WebServer] Added proxy socket " << clientSd << " to tracking list." << std::endl; // debuggin
            }

            // Create and manage worker thread
            std::thread workerThread(handleRequest, clientSd);
            {
                std::lock_guard<std::mutex> lock(threadMutex);
                threads.push_back(std::move(workerThread)); // transer ownership of threads to vector (to join later )
                // std::cout << "[WebServer] Launched thread " << threads.back().get_id() << " for socket " << clientSd << std::endl; // debugging
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[WebServer] Error creating thread: " << e.what() << '\n';
            removeClientSocket(clientSd);
            close(clientSd);
        }
    }

    std::cout << "[WebServer] Server loop finished." << std::endl;
    return 0;
}