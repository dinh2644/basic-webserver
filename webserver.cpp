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
    std::cout << "Attempting to remove socket: " << sd << std::endl; // Debugging
    clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), sd), clientSockets.end());
    std::cout << "Current client sockets: "; // Debugging
    for (int s : clientSockets)
        std::cout << s << " "; // Debugging
    std::cout << std::endl;    // Debugging
}

void signalHandler(int signum)
{
    std::cout << "\n[" << std::this_thread::get_id() << "] Signal " << signum << " received. Shutting down server safely...\n";
    serverRunning = false;

    // Cause accept() to return by connecting to the server yourself (Optional)
    // This prevents scenario if accept() is blocked indefinitely
    std::cout << "Attempting to unblock accept()...\n"; // Debugging
    int dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (dummy_sock >= 0)
    {
        sockaddr_in servAddr;
        bzero((char *)&servAddr, sizeof(servAddr));
        servAddr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr); // connect to localhost
        servAddr.sin_port = htons(28000);                    // make sure this matches the port in main()
        // Set non-blocking connect to avoid hanging here if server already closed listen socket
        int flags = fcntl(dummy_sock, F_GETFL, 0);
        fcntl(dummy_sock, F_SETFL, flags | O_NONBLOCK);
        connect(dummy_sock, (struct sockaddr *)&servAddr, sizeof(servAddr));
        // Wake up accept()
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // brief pause
        close(dummy_sock);
        std::cout << "Dummy socket closed.\n"; // Debugging
    }
    else
    {
        std::cerr << "Could not create dummy socket to unblock accept.\n"; // Debugging
    }

    // --- New: Shutdown active client connections ---
    std::cout << "Shutting down active client connections...\n";
    {
        std::lock_guard<std::mutex> lock(clientSocketsMutex);
        std::cout << "Sockets to shutdown: "; // Debugging
        for (int s : clientSockets)
            std::cout << s << " "; // Debugging
        std::cout << std::endl;    // Debugging
        for (int clientSd : clientSockets)
        {
            std::cout << "Shutting down SD: " << clientSd << std::endl; // Debugging
            if (shutdown(clientSd, SHUT_RDWR) < 0)
            {
                perror("shutdown error");
            }
        }
    }
    // Give threads a moment to react to socket shutdown/errors
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Join all active threads before shutdown
    std::cout << "Waiting for active connections to close...\n";
    {
        std::lock_guard<std::mutex> lock(threadMutex);
        std::cout << "Joining " << threads.size() << " threads.\n"; // Debugging

        for (auto &t : threads)
        {
            if (t.joinable())
            {
                std::cout << "Joining thread " << t.get_id() << std::endl; // Debugging

                t.join();
                std::cout << "Joined thread " << t.get_id() << std::endl; // Debugging
            }
            else
            {
                std::cout << "Thread " << t.get_id() << " not joinable.\n"; // Debugging
            }
        }
        threads.clear();
        std::cout << "Threads vector cleared.\n"; // Debugging
    }

    std::cout << "Closing server listener socket...\n";
    close(serverSd);
    std::cout << "-- Server shutdown complete --" << std::endl;

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
void handleThreads(int newSd)
{
    // RAII for socket descriptor - manages close() and removal from global list
    SocketCloser socket_closer(newSd);

    std::cout << "[" << std::this_thread::get_id() << "] Handling connection on socket " << newSd << "\n"; // Debugging

    // Globals
    std::string successMsg = "HTTP/1.1 200 OK\r\n";
    std::string notFoundMsg = "HTTP/1.1 404 Not Found\r\n";
    std::string html404Body = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource could not be found on this server.</p></body></html>";
    notFoundMsg += "Content-Type: text/html; charset=utf-8\r\n";
    notFoundMsg += "Content-Length: " + std::to_string(html404Body.length()) + "\r\n";
    notFoundMsg += "\r\n";
    notFoundMsg += html404Body;

    // Retrieve http request msg
    const int buffer_size = 8192;
    char buffer[buffer_size] = {0};
    ssize_t bytes_received = recv(newSd, buffer, buffer_size - 1, 0);
    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            std::cout << "[" << std::this_thread::get_id() << "] Client disconnected socket " << socket_closer.sd << "\n"; // Debugging
        }
        else
        {
            perror("recv error");                                                                                    // Debugging
            std::cout << "[" << std::this_thread::get_id() << "] Recv error on socket " << socket_closer.sd << "\n"; // Debugging
        }
        return; // SocketCloser destructor will handle cleanup
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

    std::string file_path = request_uri.substr(1);

    // Handle invalid path (also prevent directory traversal)
    if (file_path.empty() || file_path.find("..") != std::string::npos)
    {
        send(newSd, notFoundMsg.c_str(), notFoundMsg.length(), 0);
        std::cout << "File path empty\n";
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
        send(newSd, notFoundMsg.c_str(), notFoundMsg.length(), 0);
        std::cout << "Unsupported file type requested: " << file_path << "\n";
        return;
    }

    // Check in server if file exists
    if (!fileExists(file_path))
    {
        send(newSd, notFoundMsg.c_str(), notFoundMsg.length(), 0);
        std::cout << "HTTP/1.1 404 Not Found\n";
        return;
    }

    // Send file content
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        send(newSd, notFoundMsg.c_str(), notFoundMsg.length(), 0);
        std::cout << "File exists but cannot be opened: " << file_path << "\n";
        return;
    }

    std::streamsize fileSize = file.tellg(); // get file size
    file.seekg(0, std::ios::beg);            // seek back to beginning

    // Construct success headers
    std::string headers = successMsg;
    headers += "Content-Type: " + contentType + "\r\n";
    headers += "Content-Length: " + std::to_string(fileSize) + "\r\n";
    headers += "\r\n"; // http header separator

    // Send headers
    ssize_t sent_bytes = send(newSd, headers.c_str(), headers.length(), 0);
    if (sent_bytes < 0 || (size_t)sent_bytes != headers.length())
    {
        std::cerr << "Error sending headers for " << file_path << std::endl;
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
            std::cerr << "Server shutting down during file transfer for " << file_path << "\n";
            break; // Exit loop, SocketCloser will handle cleanup
        }

        ssize_t current_chunk_size = file.gcount();
        ssize_t chunk_sent_bytes = send(socket_closer.sd, fileBuffer, current_chunk_size, 0); // Use socket_closer.sd

        if (chunk_sent_bytes < 0)
        {
            // Error occurred (e.g. client disconnected, or shutdown() called from signal handler)
            std::cerr << "Error sending file content chunk for " << file_path << " (socket: " << socket_closer.sd << ")" << "\n";
            perror("send error detail"); // Debugging
            break;
        }
        if ((size_t)chunk_sent_bytes != current_chunk_size)
        {
            // For simplicity, treat this section as an error condition and break. (this should rarely occur w/ blocking sockets error)
            // For future reference: handle trying to send remaining chunks?
            std::cerr << "Warning: Sent fewer bytes than expected for chunk: " << chunk_sent_bytes << "/" << current_chunk_size << "\n";
            break;
        }
    }
    std::cout << "[" << std::this_thread::get_id() << "] Response sent for: " << file_path << " on socket " << socket_closer.sd << "\n";
}

/*
 *********************************************************** Main ***********************************************************
 */

int main(int argc, char *argv[])
{
    // For the server, we only need to specify a port number
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        exit(1);
    }
    // Grab the port number
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535)
    {
        std::cerr << "Invalid port number: " << argv[1] << std::endl;
        exit(1);
    }

    // Setup signal handler for SIGINT (Ctrl+C) and SIGTERM
    signal(SIGINT, signalHandler);  // 2
    signal(SIGTERM, signalHandler); // 15

    // Setup a socket and connection tools
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
        close(serverSd);
        exit(1);
    }

    int option = 1;
    if (setsockopt(serverSd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(serverSd);
        exit(1);
    }

    // Bind the socket to its local address
    if (bind(serverSd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        perror("Error binding socket to local address");
        close(serverSd);
        exit(1);
    }

    std::cout << "Waiting for a client to connect..." << "\n";
    // SOMAXCONN defines the maximum number allowed to pass to listen() per system
    if (listen(serverSd, SOMAXCONN) < 0)
    {
        perror("Error listening on socket");
        close(serverSd);
        exit(1);
    }

    std::cout << "Server listening on port " << port << ". Press Ctrl+C to shut down." << "\n";

    while (serverRunning)
    {
        // Receive a request from client using accept
        // We need a new address to connect with the client
        sockaddr_in newSockAddr;
        socklen_t newSockAddrSize = sizeof(newSockAddr);
        // Accept, create a new socket descriptor to
        // Handle the new connection with client
        int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);

        // Check flag immediately after accept returns
        if (!serverRunning)
        {
            if (newSd >= 0)
                close(newSd); // close newly accepted socket if shutting down
            break;            // exit loop if serverRunning is false
        }

        if (newSd < 0)
        {
            // EINTR means accept was interrupted by our signal (okay if shutting down)
            if (errno == EINTR && !serverRunning)
            {
                std::cout << "accept() interrupted gracefully during shutdown." << std::endl; // Debugging
                break;
            }
            else if (errno != EINTR) // log other errors if not shutting down
            {
                perror("Error accepting request from client");
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

        try
        {
            {
                std::lock_guard<std::mutex> lock(clientSocketsMutex);
                clientSockets.push_back(newSd);
                std::cout << "Added socket " << newSd << " to tracking list." << std::endl; // Debugging
            }

            // Handle client requests
            std::thread workerThread(handleThreads, newSd);
            {
                std::lock_guard<std::mutex> lock(threadMutex); // Protect threads vector
                threads.push_back(std::move(workerThread));
                std::cout << "Launched thread " << threads.back().get_id() << " for socket " << newSd << std::endl; // Debugging
            }

            // mainThreads.detach(); // removed due to detached threads being prone to SIGINT (just notes for future reference)
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error creating thread: " << e.what() << '\n';
            removeClientSocket(newSd);
            close(newSd);
        }
    }

    std::cout << "-- Server shutdowned (Without Signal Handler) --" << std::endl;

    return 0;
}

/*
   Notes for author:
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