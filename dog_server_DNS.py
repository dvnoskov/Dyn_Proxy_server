import binascii
from cr_dyndns_db import DynDNS
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import time
from config import route_DB,time_update_DNS,host_DNS2,log_admin,pas_admin
import requests


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))

def hex2str(h):
    return binascii.unhexlify(h)

def Start_update():
    try:
        url = "http://" + host_DNS2 + "/nic/test"
        requests.get(url, auth=(log_admin, pas_admin))
    except:
        pass
    return


def UPDATE_DYNDNS():
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(DynDNS)

    update={}
    while True:

        work = query.filter(DynDNS.STATUS == 'USER').count()
        if work >= 1:
            menu = session.query(DynDNS).filter(DynDNS.STATUS == 'USER').first()
            work_no = query.filter(DynDNS.dyndns_id == menu.dyndns_id)
            a1 = (int(menu.RDATA[0:2],16))
            a2 = (int(menu.RDATA[2:4],16))
            a3 = (int(menu.RDATA[4:6],16))
            a4 = (int(menu.RDATA[6:8],16))
            ip = str(a1) + "." + str(a2) + "." + str(a3) + "." + str(a4)
            update[(hex2str(menu.NAME).decode('utf-8'))] = ip  #
            work_no.update({DynDNS.STATUS: ("SYN")})
            session.commit()

        else:
            break


    sys = query.filter(DynDNS.STATUS == 'SYN')
    sys.update({DynDNS.STATUS: ("USER")})
    session.commit()
    session.close()

    return update


def DNS_NEW():
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(DynDNS)

    while True:
        new = query.filter(DynDNS.STATUS == 'NEW').count()
        if new >= 1:
            menu = session.query(DynDNS).filter(DynDNS.STATUS == 'NEW', DynDNS.USER == "DNS").first()
         #   print(menu.USER, menu.dyndns_id, menu.STATUS)
            new_no = query.filter(DynDNS.dyndns_id == menu.dyndns_id)
            can_ttl = float(menu.Time) + float(int(menu.TTL, 16))
           # print(time.time(), can_ttl)
            if time.time() > can_ttl:
                session.delete(menu)
                session.commit()
            else:
                new_no.update({DynDNS.STATUS: "WORK"})
                session.commit()

        else:
            break


    sys = query.filter(DynDNS.STATUS == 'WORK')
    sys.update({DynDNS.STATUS: ("NEW")})
    session.commit()
    session.close()



if __name__ == '__main__':
    Start_update()
    while True:
        try:
            DNS_NEW()
            time.sleep(time_update_DNS)
         #   print("Slept for ", time_update_DNS, " seconds")
        except:
            pass




