import socket
import binascii
from libs_server import DB_DNS_in
import time
from config import port_DNS,host_DNS
import logging
import multiprocessing
import logging.handlers



def worker(address):
    start_time = time.time()
    UDPServerSocket.sendto(binascii.unhexlify(DB_DNS_in(in_message)), address)
    duration = time.time() - start_time
    print("answear message :", clientIP,"Working in ",duration," seconds")
    return

if __name__ == '__main__':
    UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPServerSocket.bind((host_DNS, port_DNS))
    print("UDP server up and listening")

    while (True):

       try:

           loger = logging.getLogger()
           loger.setLevel(logging.DEBUG)
           h=logging.handlers.RotatingFileHandler("listen_dns_log.out",300,10)
           loger.addHandler(h)

           data = UDPServerSocket.recvfrom(1024)
           in_message = binascii.hexlify(data[0]).decode("utf-8")
           address = data[1]
           clientIP = "Client IP Address:{}".format(address)
           print("incoming message :", clientIP)
           p = multiprocessing.Process(target=worker(address))
           p.start()
       except :
          loger.debug("incoming message :" + str(clientIP)+time.ctime() )
          loger.debug(logging.exception(IndexError))#work

       finally:
           pass


