# Binghamton University, School of Computing, Spring 2025

## CS428 Project-3: Web Proxy Server

[This file uses Markdown, so please use correct Markdown syntax when editing the file]: #

### SUMMARY

[Provide a short description of your program's functionality, no more than a couple sentences]: #

This program has two servers, a web server and a proxy server that handles client requests and communicates with the web server acting as
the intermediary. Proxy web server forwards all client requests to the web server. It also sends all response from web
server back to the client.

### NOTES, KNOWN BUGS, AND/OR INCOMPLETE PARTS

[Add any notes you have here and/or any parts of the project you were not able to complete]: #

- Attached in my submission is a demo.mp4 which I didn't do in the previous project.
- The demo video ran my web server on my local machine rather than Bing's SSH, but my project was developed & tested on the SSH.
- Also, my server should now send an HTML 404 page, which I assume addresses the comment: "No error message displayed when responding with 404 status code." from previous project too.

### REFERENCES

[List any outside resources used]: #

https://www.ibm.com/docs/tr/i/7.4.0?topic=definitions-deleted-functions-c11
https://stackoverflow.com/questions/2321511/what-is-meant-by-resource-acquisition-is-initialization-raii
https://app.studyraid.com/en/read/12445/402081/move-semantics-in-raii-classes
https://stackoverflow.com/questions/10787766/when-should-i-really-use-noexcept
https://en.cppreference.com/w/cpp/language/move_assignment
https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
https://github.com/bozkurthan/Simple-TCP-Server-Client-CPP-Example/blob/master/tcp-Client.cpp
https://stackoverflow.com/questions/30799296/what-does-signalsigpipe-sig-ign-do
https://stackoverflow.com/questions/18073483/what-do-somaxconn-mean-in-c-socket-programming
https://cplusplus.com/reference/istream/istream/gcount/
https://stackoverflow.com/questions/19017651/how-to-send-files-in-chunk-using-socket-c-c?utm_source=chatgpt.com
https://cplusplus.com/reference/istream/istream/read/
https://www.boost.org/doc/libs/1_88_0/doc/html/boost_asio/example/cpp11/http/server/request_handler.cpp
https://cplusplus.com/forum/beginner/194071/

### INSTRUCTIONS

[Provide clear and complete step-by-step instructions on how to run and test your project]: #

0. Open 3 terminals

1. <br>In terminal 1: type "make"
   <br>In terminal 2: type "cd webserver/"
   <br>In terminal 3: type "cd proxyserver/"

2. <br>In terminal 2: type "./webserver 29000"
   <br>In terminal 3: type "./proxyserver 28000 127.0.0.1 29000"

3. <br>Open any browser, type/paste in example URL: http://localhost:28000/home.html

4. <br>Terminal 2 example output:
   <br>server-response, 200, 140656608601792, 2025-04-25 20:55:54
   <br>server-response, 200, 140656600209088, 2025-04-25 20:55:54

5. <br>Terminal 3 example output:
   <br>proxy-forward, server, 140717149927104, 2025-04-25 20:55:54
   <br>proxy-forward, client, 140717149927104, 2025-04-25 20:55:54
   <br>proxy-forward, server, 140717158319808, 2025-04-25 20:55:54
   <br>proxy-forward, client, 140717158319808, 2025-04-25 20:55:54
6. <br>Type "Ctrl+C" in either terminal 2 or 3 to observe termination signal outputs

### SUBMISSION

I have done this assignment completely on my own. I have not copied it, nor have I given my solution to anyone else. I understand that if I am involved in plagiarism or cheating I will have to sign an official form that I have cheated and that this form will be stored in my official university record. I also understand that I will receive a grade of "0" for the involved assignment and my grade will be reduced by one level (e.g., from "A" to "A-" or from "B+" to "B") for my first offense, and that I will receive a grade of "F" for the course for any additional offense of any kind.

By signing my name below and submitting the project, I confirm the above statement is true and that I have followed the course guidelines and policies.

- **Submission date:**
  04/25/2025

- **Team member 1 name:**
  Tu Dinh

- **Team member 1 tasks:**
  Part-1 & Submission

- **Team member 2 name (N/A, if not applicable):**
  N/A

- **Team member 2 tasks (N/A, if not applicable):**
  N/A
