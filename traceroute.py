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

# ICMP报文类型 => 回送请求报文
TYPE_ECHO_REQUEST = 8
CODE_ECHO_REQUEST_DEFAULT = 0

# ICMP报文类型 => 回送应答报文
TYPE_ECHO_REPLY = 0
CODE_ECHO_REPLY_DEFAULT = 0

# ICMP报文类型 => 数据报超时报文
TYPE_ICMP_OVERTIME = 11
CODE_TTL_OVERTIME = 0;

# ICMP报文类型 => 目的站不可达报文
TYPE_ICMP_UNREACHED = 3
CODE_NET_UNREACHED = 0
CODE_HOST_UNREACHED = 1
CODE_PORT_UNREACHED = 3

MAX_HOPS = 30  # 设置路由转发最大跳数为30
TIMEOUT = 3  # 如果一个请求超过3s未得到响应，则被认定为超时
TRIES = 1  # 对于每个中间站点，探测的次数设置为1
label = '*************{0}*************'


def check_sum(data):
    """
    计算校验和
    """
    if len(data) % 2:  # 长度为奇数，则补字节
        data += b'\x00'
    s = sum(array.array('H', data))
    s = (s & 0xffff) + (s >> 16)  # 移位计算两次，以确保高16位为0
    s += (s >> 16)
    s = ~s  # 取反
    return socket.ntohs(s & 0xffff)  # 大小端处理


def get_host_info(host_addr):
    """"
    获取相应ip地址对应的主机信息
    """
    try:
        host_info = socket.gethostbyaddr(host_addr)
    except socket.error as e:
        display = '{0} (host name could not be determined)'.format(host_addr)
    else:
        display = '{0} ({1})'.format(host_addr, host_info[0])
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
    # 先将检验和设置为0
    my_checksum = 0
    # 用进程号作标识
    my_id = os.getpid() & 0xffff
    # 序列号
    my_seq = 1

    # 打包出二进制首部
    my_header = struct.pack("bbHHh", TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST_DEFAULT, my_checksum, my_id, my_seq)
    # 以当前系统时间作为报文的数据部分
    my_data = struct.pack("d", time.time())
    # 构建一个临时的数据报
    package = my_header + my_data

    # 利用原始数据报来计算真正的校验和
    my_checksum = check_sum(package)

    # 处理校验和的字节序列类型：主机序转换为网络序
    if sys.platform == 'darwin':
        my_checksum = socket.htons(my_checksum) & 0xffff
    else:
        my_checksum = socket.htons(my_checksum)

    # 重新构建出真正的数据包
    my_header = struct.pack("bbHHh", TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST_DEFAULT, my_checksum, my_id, 1)
    ip_package = my_header + my_data
    return ip_package


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

                if after_type == TYPE_ICMP_UNREACHED:  # 目的不可达
                    print "Wrong!unreached net/host/port!"
                    break
                elif after_type == TYPE_ICMP_OVERTIME:  # 超时报文
                    print " %d rtt=%.0f ms %s" % (ttl, during_time * 1000, output)
                    continue
                elif after_type == 0:  # 应答报文
                    print " %d rtt=%.0f ms %s" % (ttl, during_time * 1000, output)
                    print "program run over!"
                    return
                else:
                    print "return type is %d , code is %d" % (after_type, after_code)
                    print "program run wrongly!"
                    return


if __name__ == "__main__":
    ip = raw_input("please input a ip address:")
    main(ip)
