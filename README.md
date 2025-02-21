# In-Memory Database Server with Efficient Request Handling

This project implements a basic **in-memory database server** written in C++ that uses advanced **socket/network programming** techniques to handle client-server communication. The server is designed for performance and scalability, supporting multiple clients with minimal latency. Key features of the system include:

- **Asynchronous I/O using `epoll` and `select/poll`**: The server uses system calls like `epoll` and `select/poll` to efficiently handle multiple simultaneous client connections in a non-blocking manner. This allows for improved scalability and responsiveness under heavy loads by enabling the server to process multiple client requests concurrently without blocking.
  
- **Operating System Calls for Efficient Resource Management**: The server makes extensive use of system calls, such as non blocking socket creation, binding, listening, and handling data transfer, to manage resources and client connections. This allows for better control over server behavior and resource utilization.

- **Batching Client Requests**: The server implements batching of incoming client requests, allowing it to handle multiple operations in a single round of processing. This reduces overhead and improves throughput by minimizing the number of context switches and system calls needed for each client interaction.

