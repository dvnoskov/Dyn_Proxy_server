from threading import Thread
from http.server import  HTTPServer
from libs_server import MyTCPHandler
from config import port_DYN_DNS,host_DNS
from socketserver import ThreadingMixIn



class ThreadedHTTPServer(ThreadingMixIn,HTTPServer):
    pass

if __name__ == '__main__':
    print("DynDNs server up and listening")
    server = ThreadedHTTPServer((host_DNS, port_DYN_DNS), MyTCPHandler)
    server = Thread(target=server.serve_forever())


