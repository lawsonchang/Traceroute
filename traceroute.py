# --coding:utf-8--

import array
import socket
import os
import sys
import struct
import time
import select

"""
TraceRoute程序的基本原理是：

当路由器收到一份IP数据报，如果该报文的TTL字段是1，则意味着它在网路中的生存周期已经消耗殆尽，本路由处理后还未到达目的主机的话，需要将该数据报丢弃，并给信源主机发送一份ICMP超时报文（包含该中间路由器的地址）。
这意味着：通过发送一份TTL字段为n的IP数据报给目的主机，就得到了该路径中的第n个路由器的IP地址。
那么我们使IP数据报的TTL字段值从1开始依次递增，就可以获得所有中间路由的ip地址。
当IP数据报到达目的主机时，由于已经到达目的主机，因此不会再发送ICMP超时报文了，而是ICMP应答报文。
通过区分收到的ICMP报文是超时报文（type=11）还是应答报文（type=0），以判断程序应该何时结束。
"""


ICMP_ECHO_REQUEST_TYPE = 8                    # ICMP请求报文的type
ICMP_ECHO_REQUEST_CODE = 0                    # ICMP请求报文的code（默认）

ICMP_ECHO_REPLY_TYPE = 0                      # ICMP应答报文的type
ICMP_OUTTIME_TYPE = 11                        # ICMP超时报文的type
ICMP_UNREACHED_TYPE = 3                       # ICMP目的不可达报文的type


MAX_HOPS = 30                                 # 最大跳数，设置为30跳
TIMEOUT = 3                                   # 路由超时，设置为3s
TRIES = 1                                     # 尝试次数，设置为1次
label = '*************{0}*************'       # 格式化输出


def check_sum(data):
    if len(data) % 2:                         # 长度为奇数，则补字节
        data += b'\x00'
    s = sum(array.array('H', data))
    s = (s & 0xffff) + (s >> 16)              # 移位计算两次，以确保高16位为0
    s += (s >> 16)
    s = ~s                                    # 取反
    return socket.ntohs(s & 0xffff)           # 大小端处理


def get_host_info(ip_addr):
    """"
    根据ip地址获取相应主机信息
    """
    try:
        host_info = socket.gethostbyaddr(ip_addr)
    except socket.error as e:
        display = '{0} (host name could not be determined)'.format(ip_addr)
    else:
        display = '{0} ({1})'.format(ip_addr, host_info[0])
    return display


def build_packet():
    """
    构建ICMP报文，首部内容如下：
    ————————————————————————————————————————
    |type (8) | code (8) | checksum (16)   |
    ————————————————————————————————————————
    |        id (16)     |  seq (16)       |
    ————————————————————————————————————————
    """

    my_data = struct.pack("d", time.time())                          # 打包数据部分

    my_check_sum = 0                                                 # 为了计算真正的检验和，暂时将检验和设置为0
    my_id = os.getpid() & 0xffff                                     # 用进程号作标识

    my_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, my_check_sum, my_id, 1)
    my_check_sum = check_sum(my_header + my_data)

    if sys.platform == 'darwin':
        my_check_sum = socket.htons(my_check_sum) & 0xffff           # 将主机序转换为网络序
    else:
        my_check_sum = socket.htons(my_check_sum)

    # 根据计算出的校验和重新打包首部
    my_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REQUEST_CODE, my_check_sum, my_id, 1)
    packet = my_header + my_data
    return packet


def main(hostname):

    print label.format(hostname)
    for ttl in xrange(1, MAX_HOPS):
        for tries in xrange(0, TRIES):

            # 创建icmp原始套接字
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            icmp_socket.settimeout(TIMEOUT)

            # 构建报文并发送
            icmp_package = build_packet()
            try:
                icmp_socket.sendto(icmp_package, (hostname, 0))
            except socket.gaierror as e:
                print "Wrong!not a effective ip address!"
                return

            # 进入阻塞态，等待接收ICMP超时报文/应答报文
            start_time = time.time()
            select.select([icmp_socket], [], [], TIMEOUT)
            end_time = time.time()
            # 计算阻塞的时间
            during_time = end_time - start_time
            if during_time >= TIMEOUT:
                print " * * * Request timed out."
                continue
            else:
                ip_package, ip_info = icmp_socket.recvfrom(1024)
                # 从IP数据报中取出ICMP报文的首部，位置在20：28，因为IP数据报首部长度为20
                icmp_header = ip_package[20:28]

                # 解析ICMP数据报首部各字段
                after_type, after_code, after_checksum, after_id, after_sequence = struct.unpack("bbHHh", icmp_header)
                output = get_host_info(ip_info[0])

                if after_type == ICMP_UNREACHED_TYPE:                                            # 目的不可达
                    print "Wrong!unreached net/host/port!"
                    break
                elif after_type == ICMP_OUTTIME_TYPE:                                            # 超时报文
                    print " %d rtt=%.0f ms %s" % (ttl, during_time*1000, output)
                    continue
                elif after_type == 0:                                                            # 应答报文
                    print " %d rtt=%.0f ms %s" % (ttl, during_time*1000, output)
                    print "program run over!"
                    return
                else:
                    print "return type is %d , code is %d" % (after_type, after_code)
                    print "program run wrongly!"
                    return


if __name__ == "__main__":
    ip = raw_input("please input a ip address:")
    main(ip)
