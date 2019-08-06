import binascii
import socket
from http.server import BaseHTTPRequestHandler
import base64
import urllib.parse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from cr_dyndns_db import DynDNS,User
import time
import json
import requests
from dog_server_DNS import UPDATE_DYNDNS
import threading
from config import route_DB,DNS_1,DNS_2,time_serwer,log_admin,pas_admin,host_DNS2,host_DNS



def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))

def hex2str(h):
    return binascii.unhexlify(h)



def send_udp_message(message, address, port):

    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        sock.settimeout(time_serwer)
        data, _ = sock.recvfrom(1024)
    except socket.error :
        sock.close()
        error = True
        return error
    else:
        sock.close()
        return binascii.hexlify(data).decode("utf-8")




class MyTCPHandler(BaseHTTPRequestHandler):

    def stop_DB(self):
        self.session.commit()
        self.session.close()
        self._lock.release()


    def do_DB(self):
        engine = create_engine(route_DB)
        self.Session = sessionmaker(bind=engine)
        self.session = self.Session()
        self.Base = declarative_base()
        self._lock = threading.Lock()
        self._lock.acquire()
        return self.session,self.Base,self.Session,self._lock.acquire


    def do_HEAD(self):
        self.send_header('Content-type', 'text/html')
        self.send_header('X-User-Status', 'vip')
        self.end_headers()


    def do_AUTHHEAD(self):
        self.send_response(401)
        text="badauth"
        self.send_header('WWW-Authenticate', 'Basic realm="DynDNS API Access"')
        self.send_header('X-UpdateCode','A')
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(text))
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        text="badagent"
        self.send_header("Content-type", "text/html")
        self.send_header('X-UpdateCode', 'A')
        self.send_header('Content-Length', len(text))
        self.do_HEAD()
        self.wfile.write(text.encode("utf-8"))


    def do_GET(self):
            if self.headers["Host"] == "members.dyndns.org":
                if self.path[0:11] == "/nic/update":
                    if self.headers['Authorization'] == None:
                        self.do_AUTHHEAD()
                    else:
                        if self.headers.get('Authorization')[0:6] == 'Basic ':
                            self.do_Authorization()
                        else:
                            self.do_AUTHHEAD()

            elif self.headers["Host"] == host_DNS:
                if self.path == "/nic/test":
                        self.send_response(200)
                        text = "test"
                        self.send_header('Content-Length', len(text))
                        self.send_header('Pragma', 'no-cache')
                        self.send_header('Cache-Control', 'no-cache')
                        self.do_HEAD()
                        self.wfile.write(text.encode("utf-8"))
                        try:
                            url = "http://" + host_DNS2 + "/nic/update"
                            requests.get(url, data=json.dumps(UPDATE_DYNDNS()), auth=(log_admin, pas_admin))
                        except:
                            pass
                else:
                    if self.path == "/nic/update":
                        if self.headers['Authorization'] == None:
                            self.do_AUTHHEAD()
                        else:
                            if self.headers.get('Authorization')[0:6] == 'Basic ':
                                self.do_Authorization()
                            else:
                                self.do_AUTHHEAD()
                    else:
                        pass


            elif self.headers["Host"] == "checkip.dyndns.com":     #
                if self.path == "/":  #checkip.dyndns.com
                   self.send_response(200)
                   text="<html><head><title>Current IP Check</title></head><body>Current IP Address: "+str(self.client_address[0])+"</body></html>"
                   self.send_header('Content-Length', len(text))
                   self.send_header('Pragma', 'no-cache')
                   self.send_header('Cache-Control', 'no-cache')
                   self.do_HEAD()
                   self.wfile.write(text.encode("utf-8"))
                else:
                    pass
            else:
                self.send_response(404)  # no route
                text = "404"
                self.send_header('X-UpdateCode', 'X')
                self.send_header('Content-Length', len(text))
                self.do_HEAD()
                self.wfile.write(text.encode("utf-8"))


    def do_Authorization(self):
        aut_in = (base64.b64decode((self.headers["Authorization"][6:])).decode('utf-8'))
        autoriz = aut_in.split(":")
        self.user = autoriz[0]
        login = autoriz[1]
        self.do_DB()
        query = self.session.query(User)
        filt0 = query.filter(User.username == self.user or User.password == login).first()
        if filt0 is  None:
            self.stop_DB()
            self.do_AUTHHEAD()
        else:
            filt1 = query.filter( User.password == login or User.username == self.user).first()
            if filt1 is None:
                self.stop_DB()
                self.do_AUTHHEAD()
            else:
                self.stop_DB()
                self.do_Requst_get()


    def do_Requst_get(self):
        if self.user != "admin":
            parse = dict(urllib.parse.parse_qsl(qs=self.requestline, keep_blank_values=True))
            homename_in = parse.get('hostname')
            if parse.get('myip') == "" :
                myip_in = self.client_address[0]
            else:
                myip_in = str(parse.get('myip'))


            ip = myip_in.split(".")
            s = [int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3][0:4])]
            rdata_in = str(binascii.hexlify(bytes(bytearray(s))))[2:10]
            homenam_in = (binascii.hexlify(bytes(str.encode(homename_in)))).decode('utf-8')
            self.do_DB()
            query = self.session.query(DynDNS)
            filt2 = query.filter(DynDNS.NAME == homenam_in or DynDNS.USER == self.user and DynDNS.RDATA == rdata_in).first()
            if filt2 is None:
                self.stop_DB()
                self.send_response(200)
                text = 'dnserr'
                self.send_header('X-UpdateCode', 'A')
                self.send_header('Content-Length', len(text))
                self.do_HEAD()
                self.wfile.write(text.encode("utf-8"))
            else:
                filt3 = query.filter(
                    DynDNS.USER == self.user or DynDNS.NAME == homenam_in and DynDNS.RDATA == rdata_in).first()
                if filt3 is None:
                    self.stop_DB()
                    self.send_response(200)
                    text = 'nohost'
                    self.send_header('X-UpdateCode', 'A')
                    self.send_header('Content-Length', len(text))
                    self.do_HEAD()
                    self.wfile.write(text.encode("utf-8"))
                else:
                    filt4 = query.filter(
                        DynDNS.USER == self.user or DynDNS.RDATA == rdata_in and DynDNS.NAME == homenam_in).first()
                    if filt4 is None:
                        filt5 = query.filter(DynDNS.USER == self.user, DynDNS.NAME == homenam_in)
                        filt5.update({DynDNS.RDATA: rdata_in})
                        self.stop_DB()
                        self.send_response(200)
                        text = "good   " + str(myip_in)
                        self.send_header('X-UpdateCode', 'A')
                        self.send_header('Content-Length', len(text))
                        self.do_HEAD()
                        self.wfile.write(text.encode("utf-8"))
                        try:
                            url = "http://" + host_DNS2 + "/nic/update"
                            out_data = {}
                            out_data[homename_in]= myip_in
                            requests.get(url, data=json.dumps(out_data), auth=(log_admin, pas_admin))
                        except:
                            pass
                    else:
                        self.stop_DB()
                        self.send_response(200)
                        text = "nochg"
                        self.send_header('X-UpdateCode', 'A')
                        self.send_header('Content-Length', len(text))
                        self.do_HEAD()
                        self.wfile.write(bytes(text.encode("utf-8"))) # 2 povtora

        else:
            content_length = int(self.headers['Content-Length'])  # w
            upd_dat = str(self.rfile.read(content_length))[2:-2]  # w
            autoriz = upd_dat.split(",")
            i = 0
            while True:
                if i <= len(autoriz) - 1:
                    nam = autoriz[i].split(":")
                    homename_in = nam[0][2:-1]
                    myip_in = nam[1][2:-1]
                    ip = myip_in.split(".")
                    s = [int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])]
                    rdata_in = str(binascii.hexlify(bytes(bytearray(s))))[2:10]
                    homenam_in = (binascii.hexlify(bytes(str.encode(homename_in)))).decode('utf-8')
                    self.do_DB()
                    query = self.session.query(DynDNS)
                    filt2 = query.filter(DynDNS.NAME == homenam_in).first()
                    if filt2 is not None:
                        filt5 = query.filter(DynDNS.NAME == homenam_in)
                        filt5.update({DynDNS.RDATA: rdata_in})
                        self.stop_DB()
                        i = i + 1
                    else:
                        i = i + 1
                        self.stop_DB()

                else:
                    break
            text = "good update"
            self.send_response(200)
            self.send_header('X-UpdateCode', 'A')
            self.send_header('Content-Length', len(text))
            self.do_HEAD()
            self.wfile.write(text.encode("utf-8"))



def answer_no_name(List_db_dns_in):
    List_db_dns_out = {}
    List_db_dns_out["ID"] = List_db_dns_in["ID"]
    List_db_dns_out["QR"] = "1"  # 0-requst , 1 answer
    List_db_dns_out["OPCODE"] = List_db_dns_in["OPCODE"]  # 0- standart requst and variant
    List_db_dns_out["AA"] = List_db_dns_in["AA"]  # Code answer
    List_db_dns_out["TC"] = List_db_dns_in["TC"]  # TrunCation
    List_db_dns_out["RD"] = "1"  # Recursion
    List_db_dns_out["RA"] = "1"  # Recursion Available
    List_db_dns_out["Z"] = "000"  # Reservation
    List_db_dns_out["RCODE"] = "0010"  # Code answer(0,1,2,3,4,5,6-15) Server failure
    List_db_dns_out["QDCOUNT"] = List_db_dns_in["QDCOUNT"]  # 1-requst
    List_db_dns_out["ANCOUNT"] = "0000"  # Code answer 1  one  count db
    # List_db_dns_out["NSCOUNT"]= requst.dns_id  # format data xxxx
    List_db_dns_out["NSCOUNT"] = List_db_dns_in["NSCOUNT"]  # numba write name servis available  #default 0000
    List_db_dns_out["ARCOUNT"] = List_db_dns_in["ARCOUNT"]  # numba write recurs additionally
    List_db_dns_out["QNAME"] = List_db_dns_in["QNAME"]
    List_db_dns_out["QTYPE"] = List_db_dns_in["QTYPE"]
    List_db_dns_out["QCLASS"] = List_db_dns_in["QCLASS"]
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") + List_db_dns_out.get("TC") \
               + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0001"
    List_db_dns_out["CLASS"] = "0001"
    List_db_dns_out["TTL"] = "0000"
    List_db_dns_out["RDLENGTH"] = "0004"
    List_db_dns_out["RDATA"] = "00000000"
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA")
    return message_db_dns_out




def DB_DNS_add(in_message):
    # distionary incoming message
    #
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(DynDNS)


    List_db_dns_in = {}
    List_db_dns_in["ID"] = in_message[0:4]
    if List_db_dns_in.get("ID") == "a0a0" or List_db_dns_in.get("ID") == "A0A0":  # message answer dns
        id2 = bin(int((in_message[4:8]), 16))
        List_db_dns_in["QR"] = id2[2]
        List_db_dns_in["OPCODE"] = id2[3:7]
        List_db_dns_in["AA"] = id2[7]
        List_db_dns_in["TC"] = id2[8]
        List_db_dns_in["RD"] = id2[9]
        List_db_dns_in["RA"] = id2[10]
        List_db_dns_in["Z"] = id2[11:14]
        List_db_dns_in["RCODE"] = id2[14:18]
        List_db_dns_in["QDCOUNT"] = in_message[8:12]
        List_db_dns_in["ANCOUNT"] = in_message[12:16]
        List_db_dns_in["NSCOUNT"] = in_message[16:20]
        List_db_dns_in["ARCOUNT"] = in_message[20:24]
        i = (int((in_message[24:26]), 16))
        y = i

        while True:
            if (in_message[(26 + y * 2):(28 + y * 2)]) == "00":
                z = y
                List_db_dns_in["QNAME"] = in_message[24:28 + y * 2]
                break
            else:
                i = (int((in_message[(26 + y * 2):(28 + y * 2)]), 16))
                y = y + i + 1

        List_db_dns_in["QTYPE"] = in_message[(28 + z * 2):(32 + z * 2)]
        List_db_dns_in["QCLASS"] = in_message[(32 + z * 2):(36 + z * 2)]
        id3 = bin(int(in_message[(36 + z * 2):(40 + z * 2)], 16))
        if id3[2:4] == "11":
            List_db_dns_in["NAME"] = in_message[(36 + z * 2):(40 + z * 2)]
        else:
            return
            #   return print('NAME adress non Available')

        List_db_dns_in["TYPE"] = in_message[(40 + z * 2):(44 + z * 2)]
        List_db_dns_in["CLASS"] = in_message[(44 + z * 2):(48 + z * 2)]
        List_db_dns_in["TTL"] = in_message[(48 + z * 2):(56 + z * 2)]
        if in_message[(56 + z * 2):(60 + z * 2)] == "0004":
            List_db_dns_in["RDLENGTH"] = in_message[(56 + z * 2):(60 + z * 2)]
        else:
            return
            #  return print('ip adress non Available')

        if List_db_dns_in["ANCOUNT"] == "0001":
            List_db_dns_in["RDDATA"] = in_message[(60 + z * 2):(68 + z * 2)]
        elif List_db_dns_in["ANCOUNT"] == "0002":
            List_db_dns_in["RDDATA"] = in_message[(60 + z * 2):(100 + z * 2)]
        elif List_db_dns_in["ANCOUNT"] == "0003":
            List_db_dns_in["RDDATA"] = in_message[(60 + z * 2):(140 + z * 2)]
        elif List_db_dns_in["ANCOUNT"] == "0004":
            List_db_dns_in["RDDATA"] = in_message[(60 + z * 2):(180 + z * 2)]
        elif List_db_dns_in["ANCOUNT"] == "0005":
            List_db_dns_in["RDDATA"] = in_message[(60 + z * 2):(220 + z * 2)]
        List_db_dns_in["List_db_dns_in"] = in_message

        # add db  # write A # 1 internet
        if List_db_dns_in["QTYPE"] == "0001" and List_db_dns_in["QCLASS"] == "0001" and List_db_dns_in[
            "RCODE"] == "0000":
            id4 = bin(int(List_db_dns_in.get("NAME"), 16))
            stpname = int(id4[4:18], 2)
            name_lend = int(List_db_dns_in.get("List_db_dns_in")[0 + stpname * 2:2 + stpname * 2])
            start_ind = 2 + stpname * 2
            stop_ind = 2 + stpname * 2 + name_lend * 2
            name = List_db_dns_in.get("List_db_dns_in")[start_ind:stop_ind]
            s = 2
            nam_lend = int(List_db_dns_in.get("List_db_dns_in")[stop_ind:2 + stop_ind], 16)

            while True:
                if nam_lend == 00:
                    break

                else:
                    start_ind = s + stop_ind
                    stop_ind = s + stop_ind + nam_lend * 2
                    name = name + "2e" + (List_db_dns_in.get("List_db_dns_in")[start_ind:stop_ind])
                    nam_lend = int(List_db_dns_in.get("List_db_dns_in")[stop_ind:2 + stop_ind], 16)

            DB_DynDNS_add = DynDNS(NAME=name,
                                       USER="DNS",
                                       TYPE=List_db_dns_in.get("TYPE"),
                                       CLASS=List_db_dns_in.get("CLASS"),
                                       TTL=List_db_dns_in.get("TTL"),
                                       ANCOUNT=List_db_dns_in.get("ANCOUNT"),
                                       RDLENGTH=List_db_dns_in.get("RDLENGTH"),
                                       RDATA=List_db_dns_in.get("RDDATA"),
                                       Time=time.time(),
                                       STATUS="NEW")
            session.add(DB_DynDNS_add)
            session.commit()
            session.close()

        else:
            return


def DB_DNS_in(in_message):
    # distionary incoming message
    #
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(DynDNS)
    #

    List_db_dns_in = {}
    List_db_dns_in["ID"] = in_message[0:4]
    id2 = bin(int((in_message[4:8]), 16))
    List_db_dns_in["QR"] = id2[2]
    List_db_dns_in["OPCODE"] = id2[3:7]
    List_db_dns_in["AA"] = id2[7]
    List_db_dns_in["TC"] = id2[8]
    List_db_dns_in["RD"] = id2[9]
    List_db_dns_in["RA"] = id2[10]
    List_db_dns_in["Z"] = id2[11:14]
    List_db_dns_in["RCODE"] = id2[14:18]
    List_db_dns_in["QDCOUNT"] = in_message[8:12]
    List_db_dns_in["ANCOUNT"] = in_message[12:16]
    List_db_dns_in["NSCOUNT"] = in_message[16:20]
    List_db_dns_in["ARCOUNT"] = in_message[20:24]
    i = (int((in_message[24:26]), 16))
    y = i

    while True:
        if (in_message[(26 + y * 2):(28 + y * 2)]) == "00":
            z = y
            List_db_dns_in["QNAME"] = in_message[24:28 + y * 2]
            break
        else:
            i = (int((in_message[(26 + y * 2):(28 + y * 2)]), 16))
            y = y + i + 1

    List_db_dns_in["QTYPE"] = in_message[(28 + z * 2):(32 + z * 2)]
    List_db_dns_in["QCLASS"] = in_message[(32 + z * 2):(36 + z * 2)]
    List_db_dns_in["List_db_dns_in"] = in_message
    l = (int((List_db_dns_in.get("QNAME")[0:2]), 16))
    qname = (List_db_dns_in.get("QNAME")[2: 2 + l * 2])
    while True:
        if (List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2]) == "00":
            break
        else:
            m = int(List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2], 16)
            qname = qname + "2e" + (List_db_dns_in.get("QNAME")[4 + l * 2:4 + (l + m) * 2])
            l = l + m + 1

    requst = session.query(DynDNS).filter(DynDNS.NAME == qname).first()
    if requst is not None:
        List_db_dns_out = {}
        List_db_dns_out["ID"] = List_db_dns_in["ID"]
        List_db_dns_out["QR"] = "1"  # 0-requst , 1 answer
        List_db_dns_out["OPCODE"] = List_db_dns_in["OPCODE"]  # 0- standart requst and variant
        List_db_dns_out["AA"] = List_db_dns_in["AA"]  # Code answer
        List_db_dns_out["TC"] = List_db_dns_in["TC"]  # TrunCation
        List_db_dns_out["RD"] = "1"  # Recursion
        List_db_dns_out["RA"] = "1"  # Recursion Available
        List_db_dns_out["Z"] = "000"  # Reservation
        l = (int((List_db_dns_in.get("QNAME")[0:2]), 16))
        qname = (List_db_dns_in.get("QNAME")[2: 2 + l * 2])
        while True:
            if (List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2]) == "00":
                break
            else:
                m = int(List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2], 16)
                qname = qname + "2e" + (List_db_dns_in.get("QNAME")[4 + l * 2:4 + (l + m) * 2])
                l = l + m + 1


        requst = session.query(DynDNS).filter(DynDNS.NAME == qname).first()
        List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
        List_db_dns_out["QDCOUNT"] = List_db_dns_in["QDCOUNT"]  # 1-requst
        List_db_dns_out["ANCOUNT"] = requst.ANCOUNT  # Code answer 1  one  count db
        List_db_dns_out["NSCOUNT"] = List_db_dns_in["NSCOUNT"]  # numba write name servis available  #default 0000
        List_db_dns_out["ARCOUNT"] = List_db_dns_in["ARCOUNT"]  # numba write recurs additionally
        List_db_dns_out["QNAME"] = List_db_dns_in["QNAME"]
        List_db_dns_out["QTYPE"] = List_db_dns_in["QTYPE"]
        List_db_dns_out["QCLASS"] = List_db_dns_in["QCLASS"]
        Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
            "AA") + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
        Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
        Header_1_1 = Header_1[0:4]
        Header_1_2 = Header_1[4:8]
        Header_2_1 = Header_2[0:4]
        Header_2_2 = Header_2[4:8]
        List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                    + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
        List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
        List_db_dns_out["TYPE"] = requst.TYPE
        List_db_dns_out["CLASS"] = requst.CLASS
        List_db_dns_out["TTL"] = requst.TTL
        List_db_dns_out["RDLENGTH"] = requst.RDLENGTH
        List_db_dns_out["RDATA"] = requst.RDATA
        message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                             + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                             + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                             + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                             + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                             + List_db_dns_out.get("RDATA")
        session.commit()
        session.close()
    else:
        Query_message_dns_1= "A0A0"+List_db_dns_in.get('List_db_dns_in')[4:]
        response = send_udp_message(Query_message_dns_1, DNS_1, 53)
        if response != True:
             message_db_dns_out = List_db_dns_in.get("ID")+response[4:]
             DB_DNS_add(response)
        else:
            response = send_udp_message(Query_message_dns_1, DNS_2, 53)
            if response != True:
                message_db_dns_out = List_db_dns_in.get("ID") + response[4:]
                DB_DNS_add(response)
            else:
                message_db_dns_out = answer_no_name(List_db_dns_in)

    session.commit()
    session.close()
    return message_db_dns_out

