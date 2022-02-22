#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8005 Network Security & Applications Development
Assignment 3
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 6J
----------------------------------------------------------------------------------------------------
server.py
    The server of a client/server implemented with epoll (edge-triggered) asynchronous server.
    Designed to handle large number of client connections from several machines.
    Epoll Server acts like an extended echo server.
    Implements extensive logging of statistics to facilitate scalability and performance stress testing.
----------------------------------------------------------------------------------------------------
"""
import time
from socket import *
from _thread import *
from contextlib import contextmanager
import socket
import select


class ServerSummary:
    """
    Holds varies statistics summarize scalability and performance stress test for the epoll server.
    """
    def __init__(self, host_ip):
        self.host_ip = host_ip
        self.total_client_conns = 0
        self.total_client_echo_req = 0
        self.total_data_recv = 0
        self.total_data_sent = 0


class ClientSocketInfo:
    """
    Holds varies statistics of individual client connections for further processing and to log.
    """
    def __init__(self, sock):
        self.sock = sock
        self.echo_request = ''
        self.total_requests = 0
        self.total_data_recv = 0
        self.total_data_sent = 0


LOG_PATH = "server_log.txt"
CONFIGURATION_PATH = "server_configuration.txt"
BUFFER_SIZE = 1024
clients_summary = {}
configuration = {
    'server_address': '',
    'server_port': '',
    'server_listen_backlog': 0
}


def read_configuration():
    """
    Reads configuration file and set Epoll Server variables.
    :return: None
    """
    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            config_data = line.split('=')
            if config_data[0] in configuration:
                if config_data[0] == 'server_address':
                    configuration[config_data[0]] = config_data[1]
                else:
                    data = config_data[1]
                    if data.isdigit():
                        configuration[config_data[0]] = int(config_data[1])
                    else:
                        print("Invalid configuration, config other than server address should be integers.")
                        exit()


def start_epoll_server():
    """
    Main Epoll Server Function
    Initialize the non-blocking socket with select and epoll to accept client connections for extended echo.

    Epoll watches for 3 main events:
        Epoll Socket Event:
            If event is from epoll server listening socket, accept client connection.
        Read Event:
            If event is socket available to read (client echo request), receive message.
        Write Event:
            If event is socket available to write (server echo response), send message.
            
    :return: None
    """
    with socket_context_manager(AF_INET, SOCK_STREAM) as server, epoll_context_manager(server.fileno(), select.EPOLLIN) as epoll:

        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow multiple bindings to port

        server.bind((configuration['server_address'], configuration['server_port']))
        server.listen(configuration['server_listen_backlog'])

        server.setblocking(False)
        server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Set socket to non-blocking options
        print(f"Listening on: {configuration['server_address']}, {configuration['server_port']}")

        client_sockets = {}

        while True:
            events = epoll.poll(1)

            for sockdes, event in events:
                # If event is from epoll server listening socket, accept client connection.
                if sockdes == server.fileno():
                    accept_connection(server, client_sockets, epoll)

                # If event is socket available to read (client echo request), receive message.
                elif event & select.EPOLLIN:
                    receive_handler(sockdes, client_sockets, epoll)

                # If event is socket available to write (server echo response), send message.
                elif event & select.EPOLLOUT:
                    send_handler(sockdes, client_sockets, epoll)


def accept_connection(server, client_sockets, epoll):
    """
    Processes new client connections, and register the connection to epoll.
    :param server: server socket
    :param client_sockets: dictionary of active client sockets
    :param epoll: epoll reference
    :return: None
    """
    connection, address = server.accept()
    connection.setblocking(0)

    print(f'Client {connection.fileno()} Connected: {address}')  # print client IP
    ip_address = address[0]
    if ip_address not in clients_summary:
        clients_summary[ip_address] = ServerSummary(ip_address)

    clients_summary[ip_address].total_client_conns += 1

    client_sock_info = ClientSocketInfo(connection)
    fd = connection.fileno()
    epoll.register(fd, select.EPOLLIN)
    client_sockets[fd] = client_sock_info


def receive_handler(sockdes, client_sockets, epoll):
    """
    Handles receiving client request messages, and trigger an echo response from server back to client.
    :param sockdes: client socket number
    :param client_sockets: dictionary of active client sockets
    :param epoll: epoll reference
    :return: None
    """
    conn = client_sockets[sockdes].sock
    data = conn.recv(BUFFER_SIZE).decode('utf-8')
    # Check if connection still open
    if data:
        client_sockets[sockdes].total_requests += 1
        client_sockets[sockdes].total_data_recv += len(data)
        client_sockets[sockdes].echo_request = data
        clients_summary[conn.getpeername()[0]].total_client_echo_req += 1  # log
        clients_summary[conn.getpeername()[0]].total_data_recv += len(data)  # log
        epoll.modify(sockdes, select.EPOLLOUT)
    else:
        print_connection_results(sockdes, client_sockets)
        epoll.unregister(sockdes)
        client_sockets[sockdes].sock.close()
        del client_sockets[sockdes]
        return


def send_handler(sockdes, client_sockets, epoll):
    """
    Handles sending server's echo responses to the client messages.
    :param sockdes: client socket number
    :param client_sockets: dictionary of active client socket
    :param epoll: epoll reference
    :return: None
    """
    client_sockets[sockdes].sock.send(client_sockets[sockdes].echo_request.encode('utf-8'))
    data_len = len(client_sockets[sockdes].echo_request)
    clients_summary[client_sockets[sockdes].sock.getpeername()[0]].total_data_sent += data_len  # log
    client_sockets[sockdes].total_data_sent += data_len
    epoll.modify(sockdes, select.EPOLLIN)


def print_summary():
    """
    Prints summary all connections from all hosts received by server, and their activities.
    :return: None
    """
    log_data = f''
    log_data += (
        f'------------------------------------------------------------------\n'
        f'Server Summary:\n'
        f'------------------------------------------------------------------\n'
        f'Total Remote Hosts: {len(clients_summary)}\n'
    )
    for key, client in clients_summary.items():
        log_data += (
            f"\n[{client.host_ip}]:\n"
            f"    Total connections = {client.total_client_conns}\n"
            f"    Total echo requests = {client.total_client_echo_req}\n"
            f"    Total data recv = {client.total_data_recv}\n"
            f"    Total data sent = {client.total_data_sent}\n"
        )
    log_data += '------------------------------------------------------------------\n'
    print(log_data)
    with open(file=LOG_PATH, mode="a", encoding='utf-8') as file:
        file.write(log_data)


def print_connection_results(sockdes, client_sockets):
    """
    Prints a summary of a single client socket's connection activties.
    :param sockdes: client socket number
    :param client_sockets: dictionary of active client sockets
    :return: None
    """
    log_data = (
        f"[{client_sockets[sockdes].sock.getpeername()}] Connection closed, results:\n"
        f"    Total echo requests = {client_sockets[sockdes].total_requests}\n"
        f"    Total data recv = {client_sockets[sockdes].total_data_sent}\n"
        f"    Total data sent = {client_sockets[sockdes].total_data_recv}\n"
    )
    print(log_data)
    with open(file=LOG_PATH, mode="a", encoding='utf-8') as file:
        file.write(log_data)


@contextmanager
def epoll_context_manager(*args, **kwargs):
    """
    Epoll loop Context manager, use context manager to free epoll resources upon termination.
    :param args: Epoll server args
    :param kwargs: Epoll server options
    :return:
    """
    eps = select.epoll()
    eps.register(*args, **kwargs)
    try:
        yield eps
    finally:
        print_summary()
        print("\nExiting epoll loop")
        eps.unregister(args[0])
        eps.close()


@contextmanager   # Socket Context (resource) manager
def socket_context_manager(*args, **kwargs):
    sd = socket.socket(*args, **kwargs)
    try:
        yield sd
    finally:
        print("Listening Socket Closed")
        sd.close()


# Start the epoll server & Process keyboard interrupt CTRL-C
if __name__ == '__main__':
    try:
        read_configuration()
        start_epoll_server()
    except KeyboardInterrupt as e:
        print("Server Shutdown")
        exit()  # Don't really need this because of context managers
