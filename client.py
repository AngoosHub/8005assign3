#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8005 Network Security & Applications Development
Assignment 3
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 6J
----------------------------------------------------------------------------------------------------
client.py
    An extended echo client service designed to create multiple connection to a server for
    an extended duration to evaluate performance of epoll-based server.
    Implements extensive logging of statistics to facilitate scalability and performance stress testing.
    User configuration to set number of connections, data length to send, iterations for back and forth
    echos to maintain for each connection.
----------------------------------------------------------------------------------------------------
"""
import socket
import time
from socket import *
from _thread import *
import selectors


class ClientSummary:
    """
    Holds varies statistics summarize scalability and performance stress test from client to epoll server.
    """
    def __init__(self):
        self.total_clients = 0
        self.total_timeouts = 0
        self.avg_rtt = 0
        self.total_requests = 0
        self.total_data_recv = 0
        self.total_data_sent = 0
        self.program_time = 0


class ClientSocketInfo:
    """
    Holds varies statistics of individual client connections for further processing and to log.
    """
    def __init__(self, sock, iter_left):
        self.sock = sock
        self.iter_left = iter_left
        self.total_rtt = 0
        self.total_timeouts = 0
        self.total_requests = 0
        self.total_data_recv = 0
        self.total_data_sent = 0
        self.avg_rtt = 0


LOG_PATH = "client_log.txt"
CONFIGURATION_PATH = "client_configuration.txt"
sel = selectors.DefaultSelector()
clients_info = ClientSummary()
clients_sockets = {
    'uninitialized': ClientSocketInfo(None, None)
}
configuration = {
    'server_address': '',
    'server_port': 0,
    'total_client_connections': 0,
    'echo_iterations_per_client': 0,
    'echo_string': '',
    'socket_timeout': 0
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
                if config_data[0] == 'server_address' or config_data[0] == 'echo_string':
                    configuration[config_data[0]] = config_data[1]
                else:
                    data = config_data[1]
                    if data.isdigit():
                        configuration[config_data[0]] = int(config_data[1])
                    else:
                        print("Invalid configuration, config other than server_address and echo_string "
                              "should be integers.")
                        exit()


def start_client():
    """
    Initialize new client connections and registers them to selectors to handle extend echo requests.
    While loop with select continues all clients complete their iterations, then prints summary
    and exits.
    :return: None
    """
    print("Starting Connections to Server.")
    total_clients = configuration['total_client_connections']
    clients_info.program_time -= time.perf_counter()  # log

    # Start another thread to create new client connections
    print(f"Currently running...........")
    start_new_thread(initialize_connections, (total_clients,))

    try:
        while True:
            if len(clients_sockets) == 0:
                # Finish connections, exit select loop.
                break
            events = sel.select(1)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    finally:
        print_summary()
        sel.close()
        if 'uninitialized' in clients_sockets:
            del clients_sockets['uninitialized']
        for key, client_socket_info in clients_sockets.items():
            client_socket_info.sock.close()


def initialize_connections(total_conn):
    """
    Creates specified number of client connections to server.
    :param total_conn: integer of connections to make
    :return: None
    """
    for i in range(total_conn):
        sock = socket(AF_INET, SOCK_STREAM)
        try:
            client_thread(sock)
        except:
            clients_info.total_timeouts += 1
            log_data = f"Client Socket [{sock.fileno()}] dropped, failed to connected to server."
            print(log_data)
            with open(file=LOG_PATH, mode="a", encoding='utf8') as file:
                file.write(log_data)
            sock.close()
    del clients_sockets['uninitialized']


def client_thread(sock):
    """
    Creates a new socket connection to the epoll server.
    The new socket is registered in selectors to be available to write to handle maintaining
    extended echo requests up to configuration iterations.
    :return: None
    """
    HOST = configuration['server_address']
    PORT = configuration['server_port']

    clients_info.total_clients += 1
    sock.connect((HOST, int(PORT)))
    # print(f"[{sock.getsockname()}] Connected to Server: {sock.getpeername()}")
    sock.settimeout(configuration['socket_timeout'])

    client_socket_info = ClientSocketInfo(sock, configuration['echo_iterations_per_client'])
    clients_sockets[sock.fileno()] = client_socket_info
    sel.register(sock, selectors.EVENT_WRITE, client_write)


def client_read(conn, mask):
    """
    Handles reading server echo replies.
    Sets selectors back into available to write to continue extended echo.
    :param conn: client socket
    :param mask: mask for selectors event
    :return: None
    """
    try:
        data = conn.recv(1024)
        if data:
            clients_sockets[conn.fileno()].total_rtt += time.perf_counter()  # log
            clients_sockets[conn.fileno()].total_data_recv += len(data)  # log
            # print(f"echo received from server: {data.decode('utf-8')}")
            sel.modify(conn, selectors.EVENT_WRITE, client_write)
        else:
            print(f'Server closed connection: {conn.getpeername()}')
            sel.unregister(conn)
            conn.close()
    except:
        clients_sockets[conn.fileno()].total_rtt += time.perf_counter()  # log
        clients_sockets[conn.fileno()].total_timeouts += 1  # log
        print(f"Client Socket [{conn.fileno()}] has Timeout.")
        print_connection_result(conn)
        sel.unregister(conn)
        conn.close()


def client_write(conn, mask):
    """
    Handles sending an echo request to server until specified maximum iterations completed.
    Sets selectors to available to read to await server response.
    Also starts a timer to gather RTT statistics.
    :param conn: client socket
    :param mask: mask for selectors event
    :return:
    """
    iter_left = clients_sockets[conn.fileno()].iter_left
    if iter_left <= 0:
        print_connection_result(conn)
        sel.unregister(conn)
        del clients_sockets[conn.fileno()]
        conn.close()
        return
    else:
        clients_sockets[conn.fileno()].iter_left -= 1

    message = configuration['echo_string']
    clients_sockets[conn.fileno()].total_requests += 1  # log
    clients_sockets[conn.fileno()].total_data_sent += len(message)  # log
    clients_sockets[conn.fileno()].total_rtt -= time.perf_counter()  # log
    conn.sendall(message.encode('utf-8'))
    sel.modify(conn, selectors.EVENT_READ, client_read)


def print_summary():
    """
    Prints summary of connection results with epoll server, and logs it.
    :return: None
    """
    clients_info.program_time += time.perf_counter()  # log
    total_avg_response = clients_info.avg_rtt / clients_info.total_clients
    log_data = (
        f'------------------------------------------------------------------\n'
        f'Client Connection Summary:\n'
        f'------------------------------------------------------------------\n'
        f"    Total connections made = {clients_info.total_clients}\n"
        f"    Total dropped connections = {clients_info.total_timeouts}\n"
        f"    Avg RTT = {total_avg_response}\n"
        f"    Total echo requests = {clients_info.total_requests}\n"
        f"    Total data sent = {clients_info.total_data_sent}\n"
        f"    Total data recv = {clients_info.total_data_recv}\n"
        f"    Total runtime = {clients_info.program_time}\n"
        '------------------------------------------------------------------\n'
    )
    print(log_data)
    with open(file=LOG_PATH, mode="a", encoding='utf8') as file:
        file.write(log_data)


def print_connection_result(conn):
    """
    Prints individual connection results to epoll server, and logs it.
    :param conn: client socket
    :return: None
    """
    iter_left = clients_sockets[conn.fileno()].iter_left
    iter_total = configuration['echo_iterations_per_client']
    avg_resp_time = clients_sockets[conn.fileno()].total_rtt / clients_sockets[conn.fileno()].total_requests
    clients_sockets[conn.fileno()].avg_rtt = avg_resp_time
    clients_info.total_timeouts += clients_sockets[conn.fileno()].total_timeouts
    clients_info.avg_rtt += clients_sockets[conn.fileno()].avg_rtt
    clients_info.total_requests += clients_sockets[conn.fileno()].total_requests
    clients_info.total_data_recv += clients_sockets[conn.fileno()].total_data_recv
    clients_info.total_data_sent += clients_sockets[conn.fileno()].total_data_sent
    log_data = (
        f"[Socket {conn.getsockname()}] completed extended echo of {iter_total - iter_left}/{iter_total}\n"
        f"    Total drops = {clients_sockets[conn.fileno()].total_timeouts}\n"
        f"    Avg RTT = {clients_sockets[conn.fileno()].avg_rtt}\n"
        f"    Total data sent = {clients_sockets[conn.fileno()].total_data_sent}\n"
        f"    Total data recv = {clients_sockets[conn.fileno()].total_data_recv}\n"
    )
    print(log_data)
    with open(file=LOG_PATH, mode="a", encoding='utf8') as file:
        file.write(log_data)


if __name__ == "__main__":
    try:
        read_configuration()
        start_client()
    except KeyboardInterrupt as e:
        print("Client Shutdown")
        exit()
