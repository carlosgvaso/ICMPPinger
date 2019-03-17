from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_REPLY_CODE = 0
ICMP_ERROR_TYPE = 3
ICMP_DEST_NET_UNREACHABLE_CODE = 0
ICMP_DEST_HOST_UNREACHABLE_CODE = 1
ICMP_DEST_PROTO_UNREACHABLE_CODE = 2
ICMP_DEST_PORT_UNREACHABLE_CODE = 3
ICMP_DEST_NET_UNKNOWN_CODE = 6
ICMP_DEST_HOST_UNKNOWN_CODE = 7


def calcStats(rttList):
    rttMax = 0.0
    rttMin = 1.0
    rttSum = 0.0
    rttCount = 0
    lossCount = 0

    for rtt in rttList:
        if isinstance(rtt, float):
            if rtt > rttMax:
                rttMax = rtt
            if rtt < rttMin:
                rttMin = rtt
            rttSum += rtt
            rttCount += 1
        else:
            lossCount += 1

    lossRate = 100 * lossCount / (rttCount + lossCount)
    if rttCount > 0:
        rttAvg = rttSum / rttCount
    else:
        rttAvg = 'N/A'
    if rttMax == 0.0:
        rttMax = 'N/A'
    if rttMin == 1.0:
        rttMin = 'N/A'

    print('\nAvg RTT: {0}, Max RTT: {1}, Min RTT: {2}, Packet Loss Rate: {3}%'
          .format(rttAvg, rttMax, rttMin, lossRate))

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        # Fetch the ICMP header from the IP packet
        ipHeader = recPacket[:20]
        icmpHeader = recPacket[20:28]
        packetData = recPacket[28:]

        ipVersion, ipTypeOfSvc, ipLength, ipID, ipFlags, ipTTL, ipProtocol, ipChecksum, ipSrcIP, ipDestIP = \
            struct.unpack("!BBHHHBBHII", ipHeader)
        icmpType, icmpCode, icmpChecksum, packetID, packetSequence = struct.unpack('bbHHh', icmpHeader)
        timeSent = struct.unpack('d', packetData)[0]

        expectedIcmpChecksum = 0
        # Make a dummy header with a 0 checksum
        # struct -- Interpret strings as packed binary data
        header_checksum = struct.pack("bbHHh", icmpType, icmpCode, expectedIcmpChecksum, packetID, packetSequence)
        data_checksum = struct.pack("d", timeSent)
        # Calculate the checksum on the data and the dummy header.
        expectedIcmpChecksum = checksum(str(header_checksum + data_checksum))

        # Get the right checksum, and put in the header
        if sys.platform == 'darwin':
            # Convert 16-bit integers from host to network  byte order
            expectedIcmpChecksum = htons(expectedIcmpChecksum) & 0xffff
        else:
            expectedIcmpChecksum = htons(expectedIcmpChecksum)

        # Print all the values for debugging
        #print('ipSrcIP:{0}, expected: {1}'.format(ipSrcIP, destAddr))
        #print('ipTTL:{0}, expected: {1}'.format(ipTTL, '?'))
        #print('addr:{0}, expected: {1}'.format(addr[0], destAddr))
        #print('recPacket: {0}'.format(binascii.hexlify(recPacket)))
        #print('icmpHeader: {0}'.format(binascii.hexlify(icmpHeader)))
        #print('packetData: {0}'.format(binascii.hexlify(packetData)))
        #print('icmpType: {0}, expected: {1}'.format(icmpType, ICMP_ECHO_REPLY_TYPE))
        #print('icmpCode: {0}, expected: {1}'.format(icmpCode, ICMP_ECHO_REPLY_CODE))
        #print('icmpChecksum: {0}, expected: {1}'.format(icmpChecksum, expectedIcmpChecksum))
        #print('packetID: {0}, expected: {1}'.format(packetID, ID))

        # Check the received packet comes from the expected host, it has the correct ICMP type and code, check the
        # packet is not corrupted, and check this is the packet we are expecting by matching the ID and sequence numbers
        if addr[0] == destAddr and icmpType == ICMP_ECHO_REPLY_TYPE and icmpCode == ICMP_ECHO_REPLY_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return timeReceived - timeSent
        elif icmpType == ICMP_ERROR_TYPE and icmpCode == ICMP_DEST_NET_UNREACHABLE_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return 'Destination network unreachable.'
        elif icmpType == ICMP_ERROR_TYPE and icmpCode == ICMP_DEST_HOST_UNREACHABLE_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return 'Destination host unreachable.'
        elif icmpType == ICMP_ERROR_TYPE and icmpCode == ICMP_DEST_PROTO_UNREACHABLE_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return 'Destination protocol unreachable.'
        elif icmpType == ICMP_ERROR_TYPE and icmpCode == ICMP_DEST_PORT_UNREACHABLE_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return 'Destination port unreachable.'
        elif icmpType == ICMP_ERROR_TYPE and icmpCode == ICMP_DEST_NET_UNKNOWN_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return 'Destination network unknown.'
        elif icmpType == ICMP_ERROR_TYPE and icmpCode == ICMP_DEST_HOST_UNKNOWN_CODE and \
                packetID == ID and packetSequence == 1 and icmpChecksum == expectedIcmpChecksum:
            return 'Destination host unknown.'

        # Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(str(header + data))

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:
    #    http://sock-raw.org/papers/sock_raw

    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay

def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    # Send ping requests to a server separated by approximately one second
    delayList = list()
    try:
        while 1 :
            delay = doOnePing(dest, timeout)
            print(delay)
            delayList.append(delay)
            time.sleep(1)# one second
    except KeyboardInterrupt:
        calcStats(delayList)
    return delay

#ping("google.com")
