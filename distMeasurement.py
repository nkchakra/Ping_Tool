import os
import sys
import struct
import socket
import select
import time


def main():

    # setting up portno and message
    portno = 9010
    msg = 'measurement for class project. questions to student nsc27@case.edu or professor mxr136@case.edu '
    print(len(msg))

    msg = msg + ('a'*(1472 -len(msg)))
    print(len(msg))
    msgBytes = msg.encode('ascii')


    # setting up ttl for udp socks later
    ttl = 150

    filename = 'targets.txt'
    writefile = 'results6.txt'

    # read the hostnames from 'targets.txt'
    with open(filename) as f:
        targets = f.read().splitlines()

    # store the websites as tuples of (name,ip) in adds
    adds = []
    for sock in targets:
        adds.append((sock, socket.gethostbyname(sock)))

    # get output file writer
    outfile = open(writefile,"w")

    # create recv socket
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # set timmout for recv_sock
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0))

    # bind to port portno (starts server sock)
    recv_sock.bind(('', portno))

    print(adds)

    # iterate through all hosts in target.txt
    for host in adds:
        print('starting for: '+str(host))

        # create udp sock for the host, set ttl
        send = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        send.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # store time sent for RTT calc later
        sendtime = time.time()

        # send msg
        send.sendto(msgBytes, (host[1],portno))
        print('sent bytes')

        # setup some variables for loop
        maxtries = 5
        success = False;
        currTry = 0
        thisRtt = -1
        totalHops = -1
        print('pretime')

        # see if recv sock is timing out
        timeout,_,_ = select.select([recv_sock],[],[],5)
        print(timeout) # this prints a non-empty array if no timeout
        while(currTry < maxtries and success==False and timeout):
            try:
                print('waiting')

                # store received packet as payload, address
                icmp_packet, addr = recv_sock.recvfrom(2048)

                # get the end time, then calculate the RTT by endtime-sendtime
                endtime = time.time()
                print('recvd')
                thisRtt = endtime-sendtime

                # get current address of packet
                curr_addr = addr[0]
                print(curr_addr)
                length = len(icmp_packet[56:])
                print('length: '+ str(length))
                # unpack the icmp header
                icmp_header = struct.unpack("bbHHh", icmp_packet[20:28])
                #icmp_type = icmp_header[0]
                #icmp_code = icmp_header[1]
                print('icmp header: '+str(icmp_header))

                # unpack the udp header
                udp_header = struct.unpack("!HHHH",icmp_packet[48:56])
                #sourceport = udp_header[0[
                #destport = udp_header[1]
                #length = udp_header[2]
                print('udp header: '+ str(udp_header))

                # unpack the ip header
                ip_header = struct.unpack('!BBHHHBBH4s4s', icmp_packet[28:48])
                # source addr = ip_header[8]
                # dest addr = ip_header[9]
                # use socket.inet_ntoa(addr's)
                # ttl = ip_header[5]
                print('ip header: '+str(ip_header))

                # checks if this packet is one we expect
                if ((int(icmp_header[0] == 3) or int(icmp_header[1] == 3)) and udp_header[1] == portno and socket.inet_ntoa(ip_header[9]) == host[1]):
                    print('match')
                    pack_ttl = ip_header[5]
                    totalHops = ttl-pack_ttl
                    success = True


            except socket.error:
                print('sock error')
                print(socket.error)
                pass
            currTry += 1

        # this means we never received a packet
        if(thisRtt <= 0 or totalHops <= 0):
            print('no reach: '+host[0])
            outfile.write('\nhost not reachable: '+host[0])

        # print to output file the data
        else :
            outfile.write('\ndata for '+ host[0]+' is as follows: ')
            outfile.write('\n\tip: '+host[1])
            outfile.write('\n\thops: '+str(totalHops))
            outfile.write('\n\trtt: '+str(thisRtt*1000)+' ms')
            outfile.write('')
        print('closing curr sock')
        send.close()

    recv_sock.close()

if __name__ == '__main__':
        main()