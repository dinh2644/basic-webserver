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
#include <sstream> // For istringstream
#include <chrono>  // For timestamps
#include <iomanip> // For formatting timestamps
#include <ctime>   // For time functions

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

void removeClientSocket(int sd);

// RAII for socket descriptor
struct SocketCloser
{
    int sd;
    bool managed; // flag to indicate if this instance owns the socket management

    SocketCloser(int socket_descriptor) : sd(socket_descriptor), managed(true) {}

    // Prevent copying
    SocketCloser(const SocketCloser &) = delete;
    SocketCloser &operator=(const SocketCloser &) = delete;

    // Allow moving
    SocketCloser(SocketCloser &&other) noexcept : sd(other.sd), managed(other.managed)
    {
        other.managed = false; // transfer ownership
        other.sd = -1;
    }
    SocketCloser &operator=(SocketCloser &&other) noexcept
    {
        if (this != &other)
        {
            if (managed && sd >= 0)
            { // clean up existing resource (if any)
                close(sd);
                removeClientSocket(sd); // remove from global list on move assignment cleanup too
            }
            sd = other.sd;
            managed = other.managed;
            other.managed = false;
            other.sd = -1;
        }
        return *this;
    }

    ~SocketCloser()
    {
        if (managed && sd >= 0) // only close/remove if this instance manages the socket
        {
            std::cout << "Closing socket: " << sd << std::endl; // Debugging
            close(sd);
            removeClientSocket(sd); // remove from global list
        }
    }
};

void removeClientSocket(int sd)
{
    std::lock_guard<std::mutex> lock(clientSocketsMutex);
    // std::cout << "Attempting to remove socket: " << sd << std::endl; // Debugging
    clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), sd), clientSockets.end());
    std::cout << "Current client sockets: "; // Debugging
    // for (int s : clientSockets)
    //     std::cout << s << " "; // Debugging
    // std::cout << std::endl;    // Debugging
}

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

    // Cause accept() to return by connecting to the server yourself (Optional)
    // This prevents scenario if accept() is blocked indefinitely
    std::cout << "Attempting to unblock accept()...\n"; // Debugging
    int dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (dummy_sock >= 0)
    {
        sockaddr_in selfAddr;
        bzero((char *)&selfAddr, sizeof(selfAddr));
        selfAddr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &selfAddr.sin_addr); // connect to localhost

        selfAddr.sin_port = htons(8080); // make sure this matches the port in main()
        // Set non-blocking connect to avoid hanging here if server already closed listen socket
        int flags = fcntl(dummy_sock, F_GETFL, 0);
        fcntl(dummy_sock, F_SETFL, flags | O_NONBLOCK);
        connect(dummy_sock, (struct sockaddr *)&selfAddr, sizeof(selfAddr));
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // brief pause (Wake up accept())
        close(dummy_sock);
        // std::cout << "Dummy socket closed.\n"; // Debugging
    }
    // else
    // {
    //     std::cerr << "Could not create dummy socket to unblock accept.\n"; // Debugging
    // }

    // --- New: Shutdown active client connections ---
    std::cout << "[WebServer] Shutting down active client connections...\n";
    {
        std::lock_guard<std::mutex> lock(clientSocketsMutex);
        // std::cout << "Sockets to shutdown: "; // Debugging
        // for (int s : clientSockets)
        //     std::cout << s << " "; // Debugging
        // std::cout << std::endl;    // Debugging
        for (int clientSd : clientSockets)
        {
            // std::cout << "Shutting down SD: " << clientSd << std::endl; // Debugging
            if (shutdown(clientSd, SHUT_RDWR) < 0)
            {
                // Only print perror if it wasn't expected (e.g., socket already closed)
                // if (errno != ENOTCONN && errno != EPIPE) {
                //     perror("[WebServer] shutdown error");
                // }
            }
        }
    }
    // Give threads a moment to react to socket shutdown/errors
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Join all active threads before shutdown
    std::cout << "[WebServer] Waiting for active worker threads to complete...\n";
    {
        std::lock_guard<std::mutex> lock(threadMutex);
        // std::cout << "[WebServer] Joining " << threads.size() << " threads.\n"; // debug

        for (auto &t : threads)
        {
            if (t.joinable())
            {
                // std::cout << "Joining thread " << t.get_id() << std::endl; // Debugging
                t.join();
                // std::cout << "Joined thread " << t.get_id() << std::endl; // Debugging
            }
            // else
            // {
            //     std::cout << "Thread " << t.get_id() << " not joinable.\n"; // Debugging
            // }
        }
        threads.clear();
        // std::cout << "Threads vector cleared.\n"; // Debugging
    }

    std::cout << "[WebServer] Closing server listener socket...\n";
    if (serverSd >= 0)
    {
        close(serverSd);
    }
    std::cout << "[WebServer] -- Server shutdown complete --" << std::endl;
    exit(0);
}

inline bool fileExists(const std::string &fileName)
{
    struct stat buffer;
    return (stat(fileName.c_str(), &buffer) == 0);
}

/*
 *********************************************************** handleThreads ***********************************************************
 */
void handleThreads(int newSd) // handle request from proxy
{
    // RAII for socket descriptor - manages close() and removal from global list
    SocketCloser socket_closer(newSd);

    // std::cout << "[" << std::this_thread::get_id() << "] Handling connection on socket " << newSd << "\n"; // Debugging
    std::string responseCodeStr = "500"; // for internal server error

    // Retrieve http request msg
    const int buffer_size = 8192;
    char buffer[buffer_size] = {0};
    ssize_t bytes_received = recv(socket_closer.sd, buffer, buffer_size - 1, MSG_NOSIGNAL); // MSG_NOSIGNAL to prevent crashing if proxy disconnects suddenly
    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            // std::cout << "[" << std::this_thread::get_id() << "] Client disconnected socket " << socket_closer.sd << "\n"; // Debugging
        }
        else
        {
            // perror("recv error");                                                                                    // Debugging
            // std::cout << "[" << std::this_thread::get_id() << "] Recv error on socket " << socket_closer.sd << "\n"; // Debugging
        }
        return;
    }
    buffer[bytes_received] = '\0';

    // Parse http request msg
    std::string request(buffer);
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
        // std::cout << "[WebServer] Directory traversal attempt blocked: " << request_uri << std::endl; // debug
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
        // std::cout << "[WebServer] Unsupported file type requested: " << file_path << "\n"; // debug
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
        // std::cout << "[WebServer] File not found: " << file_path << "\n"; // debug
        return;
    }

    // Send file content
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::string errorMsg = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        responseCodeStr = "500";
        std::cout << "server-response, " << responseCodeStr << ", "
                  << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;
        send(socket_closer.sd, errorMsg.c_str(), errorMsg.length(), MSG_NOSIGNAL);
        // std::cerr << "[WebServer] File exists but cannot be opened: " << file_path << "\n"; // debug
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
    std::cout << "server-response, " << responseCodeStr << ", "
              << std::this_thread::get_id() << ", " << getCurrentTimestamp() << std::endl;

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
            // std::cerr << "Server shutting down during file transfer for " << file_path << "\n"; // debug
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
            // std::cerr << "Warning: Sent fewer bytes than expected for chunk: " << chunk_sent_bytes << "/" << current_chunk_size << "\n";
            break;
        }
    }
    // std::cout << "[" << std::this_thread::get_id() << "] Response sent for: " << file_path << " on socket " << socket_closer.sd << "\n";
}

/*
 *********************************************************** Main ***********************************************************
 */

int main(int argc, char *argv[])
{
    // For the server, we only need to specify a port number
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
        // close(serverSd);
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
        perror("Error listening on socket");
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
        int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);

        if (!serverRunning) // check flag immediately after accept returns
        {
            if (newSd >= 0)
                close(newSd); // close newly accepted socket if shutting down
            break;            // exit loop if serverRunning is false
        }

        if (newSd < 0) // handle accept errors
        {
            // EINTR means accept was interrupted by our signal (okay if shutting down)
            if (errno == EINTR && !serverRunning)
            {
                // std::cout << "accept() interrupted gracefully during shutdown." << std::endl; // Debugging
                break;
            }
            else if (errno != EINTR) // log other errors if not shutting down
            {
                perror("[WebServer] Error accepting request from client (proxy)");
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
            std::cout << "accept() interrupted but server still running (errno=" << errno << ")" << std::endl; // Debugging
            continue;
        }

        // Connection accepted
        try
        {
            // Add client socket (from proxy) to tracking list
            {
                std::lock_guard<std::mutex> lock(clientSocketsMutex);
                clientSockets.push_back(newSd);
                // std::cout << "[WebServer] Added proxy socket " << newSd << " to tracking list." << std::endl; // debuggin
            }

            // Create and manage worker thread
            std::thread workerThread(handleThreads, newSd);
            {
                std::lock_guard<std::mutex> lock(threadMutex); // protect threads vector
                threads.push_back(std::move(workerThread));
                // std::cout << "[WebServer] Launched thread " << threads.back().get_id() << " for socket " << newSd << std::endl; // debugging
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[WebServer] Error creating thread: " << e.what() << '\n';
            removeClientSocket(newSd); // clean up tracking vector
            close(newSd);
        }
    }

    std::cout << "[WebServer] Server loop finished." << std::endl;

    return 0;
}

/*
   Notes for myself:
   -Globals: include the trailing \r\n\r\n. This is problematic when combined with successMsg later.

   -Request reading: null-terminates, okay for simple requests but vulnerable to very long requests if exceeding buffer-size before \r\n
   Also, it only reads once, potentially missing parts of large requests (though usually the initial request line fits).

   -Request Parsing: Basic parsing of the first line. Ignores headers. Works for simple GET requests.

   -File Path Handling: file_path.empty() check is good. The subsequent !fileExists(file_path) check is also correct.
   Sending the full notFoundMsg is right. Improvement: You should handle the case where request_uri is just "/".
   Typically, this should serve a default file like "index.html".

   -File Type Detection: file_path.find(".ext") is weak. It matches the substring anywhere. E.g., my.html.backup would match .html.
   It's better to check if the string ends with the extension.

   -HTML Response Construction: Issue: This lacks a Content-Length header for the actual fileContent being sent.
   Also, htmlType incorrectly includes \r\n\r\n. The browser might render it, but it's not a standard-compliant response.

   -JPEG/PDF Response Construction: Issue: Better, but still flawed. jpegType/pdfType include \r\n\r\n.
   The first send sends the status line and the Content-Type header plus an premature end-of-headers marker.
   The second send sends the body. Crucially, there's no Content-Length header sent before the body.

   -File Reading: (string fileContent((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());)
   This reads the entire file into memory (into the fileContent string). This is simple but very inefficient for large files.
   A 1GB file would try to allocate 1GB of RAM. A better approach is to read and send the file in chunks.

   -Error Handling (ifstream::is_open): You check !file.is_open(), print an error, but you don't return.
   The code will proceed to use the invalid fileContent string, likely crashing or sending garbage.
   You need to close(newSd) and return; if the file can't be opened.

   send() Return Value: You don't check the return value of send(). It can send fewer bytes than requested, or fail entirely.
   Robust code should handle this, potentially looping until all data is sent or an error occurs.

   -Potential High Memory Usage (Not a Leak): Reading entire files into std::string can consume vast amounts of memory for large files,
   but this memory is freed when the fileContent string goes out of scope at the end of handleThreads. This isn't a leak, but it's a
   scalability issue.
   */