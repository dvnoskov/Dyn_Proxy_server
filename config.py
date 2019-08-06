#-----------------------------------------------------------------------
# config server_1
#-----------------------------------------------------------------------
#host_DNS = '127.0.0.1'  # Standard loopback interface address (localhost)
host_DNS = '192.168.1.180'  # Standard loopback interface address (localhost)
host_DNS2 ='192.168.1.190'  # Standard loopback interface address (localhost)
port_DNS = 53  # Port to listen on (non-privileged ports are > 1023)
port_DYN_DNS = 80  # Port to listen on (non-privileged ports are > 1023)
route_DB = 'sqlite:///DynDNS_server_DB'
DNS_1 = '8.8.8.8' # dns server 1
DNS_2 = '8.8.1.1' # dns server 2
time_serwer = 2 # time answer serwer DNS cek
time_update_DNS = 20 #time update DNS server
log_admin ='admin' #user admin
pas_admin ='adminKiK' # password admin