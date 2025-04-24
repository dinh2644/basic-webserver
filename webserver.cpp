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
using namespace std;

/*
 ******************* Helpers ******************
 */
int serverSd;
std::atomic<bool>
    serverRunning(true);
std::vector<std::thread> threads;
std::mutex threadMutex;

/*
TODOs:
- threads vector used at all due to using detached threads
- exit(1) may abruptly kill any running detached threads
*/

void signalHandler(int signum)
{
    cout << "\nShutting down server safely...\n";
    serverRunning = false;

    // Optional: Cause accept() to return by connecting to the server yourself
    // This helps if accept() is blocked indefinitely. Needs <netinet/in.h>, <arpa/inet.h>, <unistd.h>
    int dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (dummy_sock >= 0)
    {
        sockaddr_in servAddr;
        bzero((char *)&servAddr, sizeof(servAddr));
        servAddr.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr); // Connect to localhost
        servAddr.sin_port = htons(28000);                    // Need server's port
        connect(dummy_sock, (struct sockaddr *)&servAddr, sizeof(servAddr));
        // We don't need to do anything with this socket, just wake up accept()
        close(dummy_sock);
    }
    // Give accept() loop a moment to react to serverRunning = false
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Join all active threads before shutdown
    cout << "Waiting for active connections to close...\n";
    {
        std::lock_guard<std::mutex> lock(threadMutex);
        for (auto &t : threads)
        {
            if (t.joinable())
                t.join();
        }
        threads.clear();
    }

    close(serverSd);
    cout << "-- Server shutdowned --" << endl;

    exit(0);
}

inline bool fileExists(const string &fileName)
{
    struct stat buffer;
    return (stat(fileName.c_str(), &buffer) == 0);
}

/*
   TODOs:
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

void handleThreads(int newSd)
{
    // Globals
    string successMsg = "HTTP/1.1 200 OK\r\n";
    string htmlType = "Content-Type: text/html; charset=utf-8\r\n\r\n";
    string jpegType = "Content-Type: image/jpeg\r\n\r\n";
    string pdfType = "Content-Type: application/pdf\r\n\r\n";
    string notFoundMsg = "HTTP/1.1 404 Not Found\r\n";
    string html404Body = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested resource could not be found on this server.</p></body></html>";
    notFoundMsg += "Content-Type: text/html; charset=utf-8\r\n";
    notFoundMsg += "Content-Length: " + to_string(html404Body.length()) + "\r\n";
    notFoundMsg += "\r\n";
    notFoundMsg += html404Body;

    // Retrieve http request msg
    const int buffer_size = 8192;
    char buffer[buffer_size] = {0};
    ssize_t bytes_received = recv(newSd, buffer, buffer_size - 1, 0);
    if (bytes_received <= 0)
    {
        close(newSd);
        return;
    }
    buffer[bytes_received] = '\0';

    // Parse http request msg
    string request(buffer);
    istringstream request_stream(request);
    string request_line;
    getline(request_stream, request_line);

    // Extract "/<SOME_FILE>.extension"
    istringstream request_line_stream(request_line);
    string method, request_uri, http_version;
    request_line_stream >> method >> request_uri >> http_version;

    string file_path = request_uri.substr(1);

    // Handle invalid path (also prevent directory traversal)
    if (file_path.empty() || file_path.find("..") != std::string::npos)
    {
        send(newSd, notFoundMsg.c_str(), notFoundMsg.length(), 0);
        cout << "File path empty\n";
        close(newSd);
        return;
    }

    // Extension check
    auto ends_with = [](const string &value, const string &ending)
    {
        if (ending.size() > value.size())
            return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    };

    bool isHTML = ends_with(file_path, ".html");
    bool isJPEG = ends_with(file_path, ".jpg") || ends_with(file_path, ".jpeg");
    bool isPDF = ends_with(file_path, ".pdf");

    // Check in server if file exists
    if (!fileExists(file_path))
    {
        send(newSd, notFoundMsg.c_str(), notFoundMsg.length(), 0);
        cout << "HTTP/1.1 404 Not Found\n";
        close(newSd);
        return;
    }
    else if (isHTML)
    {
        // Prepare file for response
        ifstream file(file_path);
        if (!file.is_open())
        {
            close(newSd);
            cout << "File cannot be opened\n";
        }
        string fileContent((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

        // Send response
        string res = successMsg + htmlType + fileContent;
        send(newSd, res.c_str(), res.length(), 0);

        file.close();
        cout << "\nResponse sent\n";
    }
    else if (isJPEG)
    {
        // Prepare file for response
        ifstream file(file_path, ios::binary);
        if (!file.is_open())
        {
            close(newSd);
            cout << "File cannot be opened\n";
        }
        string fileContent((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

        // Send response
        string res = successMsg + jpegType;
        send(newSd, res.c_str(), res.length(), 0);
        send(newSd, fileContent.data(), fileContent.size(), 0);

        file.close();
        cout << "\nResponse sent\n";
    }
    else if (isPDF)
    {
        // Prepare file for response
        ifstream file(file_path, ios::binary);
        if (!file.is_open())
        {
            close(newSd);
            cout << "File cannot be opened\n";
        }
        string fileContent((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

        // Send response
        string res = successMsg + pdfType;
        send(newSd, res.c_str(), res.length(), 0);
        send(newSd, fileContent.data(), fileContent.size(), 0);

        file.close();
        cout << "\nResponse sent\n";
    }

    close(newSd);
    cout << "TCP connection closed. Waiting for next request\n";
}

/*
 ******************* Main ******************
 */

/*
TODOs:
-Thread Creation/Detach: thread mainThreads(handleThreads, newSd); mainThreads.detach();
This is the core problem related to your signal handling.
Detaching means the main thread no longer tracks or waits for this worker thread.
*/

int main(int argc, char *argv[])
{
    // for the server, we only need to specify a port number
    if (argc != 2)
    {
        cerr << "Usage: port" << endl;
        exit(0);
    }
    // grab the port number
    int port = atoi(argv[1]);

    // setup a socket and connection tools
    sockaddr_in servAddr;
    bzero((char *)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    // open stream oriented socket with internet address
    // also keep track of the socket descriptor
    serverSd = socket(AF_INET, SOCK_STREAM, 0);
    int option = 1;
    setsockopt(serverSd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (serverSd < 0)
    {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    // bind the socket to its local address
    int bindStatus = bind(serverSd, (struct sockaddr *)&servAddr,
                          sizeof(servAddr));
    if (bindStatus < 0)
    {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    // listen for up to 5 requests at a time
    listen(serverSd, 10);

    // register signal handler for SIGINT (or ctrl+c)
    // signal(SIGINT, signalHandler);
    // set server scoket to nonblocking
    // fcntl(serverSd, F_SETFL, O_NONBLOCK);

    signal(SIGINT, signalHandler);

    while (serverRunning)
    {
        // receive a request from client using accept
        // we need a new address to connect with the client
        sockaddr_in newSockAddr;
        socklen_t newSockAddrSize = sizeof(newSockAddr);
        // accept, create a new socket descriptor to
        // handle the new connection with client
        int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
        if (newSd < 0)
        {
            cerr << "Error accepting request from client!" << endl;
            exit(1);
        }

        // handle client requests with threads
        thread mainThreads(handleThreads, newSd);
        // mainThreads.detach(); // removed due to detached threads being prone to SIGINT (just notes for future reference)
    }

    cout << "-- Server shutdowned (No Ctrl+C) --" << endl;

    return 0;
}
