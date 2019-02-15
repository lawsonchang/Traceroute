# --coding:utf-8--

import socket
import os
import sys
import struct
import time
import select
import binascii

"""
TraceRoute程序的基本原理是：

当路由器收到一份IP数据报，如果TTL字段是0或者1，则路由器将该数据报丢弃，并给信源主机发送一份ICMP超时信息（包含该中间路由器的地址）。
通过发送一份TTL字段为n的IP数据报给目的主机，就得到了该路径中的第n个路由器的IP地址。
将TTL从1开始依次递增，就可以获得中间路由器的地址。
当IP数据报到达目的主机时，因为已经到达最终目的地，主机不会发送ICMP回显报文，此时程序阻塞。
等待一段时间，Tracerouter程序再发送一份UDP数据报给目的主机，但选择一个不可能的值作为目的端口号（大于30000），使得目的主机的任何一个程序都不可能使用该端口。
到达时，目的主机回送一份“端口不可达”ICMP报文，通过区分收到的ICMP报文是超时（type=11）还是目的站不可达（type=3），以判断什么时候结束。
"""

label = '*************{0}*************'
ICMP_ECHO_REQUEST_TYPE = 8      # ICMP回显请求报文type值
ICMP_ECHO_REQUEST_CODE = 0      # ICMP回显请求报文code值
MAX_HOPS = 30                   # 最大跳数
TIMEOUT = 2.0                   # 路由超时设置
TRIES = 2                       # 尝试次数


def check_sum(str):
    """
    计算ICMP报文检验和
    校验方法如下：
    1.把校验和字段置为0
    2.将icmp包（包括header和data）以16bit（2个字节）为一组，并将所有组相加（二进制求和）
    3.将高16bit与低16bit相加（反码运算的特性，进位要不直接舍弃，而是加在原结果上面，高16bit实际上是作为一个寄存器来存储是否进位了）
    4.将此16bit值进行按位求反操作，将所得值替换到校验和字段
    """
    sum = 0
    count = 0
    count_to = (len(str) / 2) * 2
    while count < count_to:
        val = ord(str[count+1]) * 256 + ord(str[count])
        sum = sum + val
        count = count + 2
        # 转换为无符号类型
        sum = sum & 0xffffffffL
    if count_to - count:
        sum = sum + ord(str[len(str) - 1])
        sum = sum & 0xffffffffL
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = (answer >> 8) | (answer << 8)
    return answer
    
def get_name_and_ip(hostip):
    try:
        host = socket.gethostbyaddr(hostip)
        nameAndIp = '{0} ({1})'.format(hostip , host[0])
    except Exception:
        nameAndIp = '{0} (host name could not be determined)'.format(hostip)
    return nameAndIp


def build_packet():
    """
    构建ICMP报文，首部内容如下：
    type (8), code (8), checksum (16), id (16), seq (16)
    """
    # 为了计算真正的检验和，暂时将检验和设置为0
    myChecksum = 0
    # 用进程号作标识
    myID = os.getpid() & 0xffff
    # struct模块可以将string直接打包为二进制数据
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    # 调用子函数计算检验和
    myChecksum = check_sum(header + data)

    if sys.platform == 'darwin':
        # 将主机序转换为网络序
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST_TYPE, 0, myChecksum, myID, 1)
    packet = header + data
    return packet


def get_route(hostname):

    print label.format(hostname)
    timeLeft = TIMEOUT

    for ttl in xrange(1,MAX_HOPS):
        for tries in xrange(TRIES):

            # 创建icmp原始套接字
            icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                destAddr = (hostname, 30001)

                # sendto()发送的就是UDP数据报
                mySocket.sendto(d, destAddr)

                # 进入阻塞态，等待接收ICMP回显应答
                # startSelect：刚开始阻塞的时间点
                # endSelect：阻塞结束的时间点
                # howLongInSelect：阻塞时长
                startedSelect = time.time()
                whetherReceiced = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = endSelect - startedSelect


                if whetherReceiced[0] == []: # 说明超时了
                    print(" * * * Request timed out.")
                recvPacket, middleAddr = mySocket.recvfrom(1024)
                timeReceived = time.time() # 读取数据的时间点
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print " * * * Request timed out."
            except socket.timeout:
                continue
            else:
                # IP数据报首部长度为20
                icmpHeaderContent = recvPacket[20:28]

                # 解析ICMP数据报首部各字段
                type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeaderContent)
                printname = get_name_and_ip(middleAddr[0])
                bytes = struct.calcsize("d")
                timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]

                if type == 11: # 网络不可达
                    print " %d rtt=%.0f ms %s" %(ttl, (endSelect - startedSelect)*1000, printname)
                elif type == 3: # 端口不可达
                    print " %d rtt=%.0f ms %s" %(ttl, (endSelect - startedSelect)*1000, printname)
                    print("33333333333")
                    print(" run over!!!")
                elif type == 0: # 到达目的主机
                    print " %d rtt=%.0f ms %s" %(ttl, (endSelect - startedSelect)*1000, printname)
                    return
                else:
                    print "error"
                break
            finally:
                mySocket.close()
if __name__ == "__main__":
    ip = raw_input("please input a ip address:")
    get_route(ip)
