#!/usr/bin/env python

import pcapy
from scapy.all import *
import threading
import dpkt
import sys
import yaml
import time
import os
import binascii
import signal
import struct


PRI_NET_RANGE = "192.168.5."
PRI_NET_CARD = "eth0"
PUB_NET_CARD = "eth1"
PUB_GW_HOST_IP = "192.168.1.92"
MOCK_GW_PORT = 9119
# PRI_GW_HOST_IP = "192.168.5.129"
PRI_NET_MOLD = "ETH"
DUMMY_NAT_TYPE = "1"
LOG_FILE_HANDLE = None
LOG_FILE_PENETRATOR = None
# FILTER_PROTOCOL_TYPE = "udp"
CHANGE_DATA_EVENT = False
CHANGE_DATA_NOT_RANDOM = True
CHANGE_DATA_POSITION = 1
CHANGE_DATA_OPERATOR = "&"
CHANGE_DATA_OPERATE_DATA = 15
CHANGE_DATA_COUNT = 1
CHANGE_DATA_CONTAIN = []

GLOBAL_IS_EXIT = False
GLOBAL_THREAD_POOL = []
NAT_ROUTE_DICT = {}
GLOBAL_COUNT_INDEX = 0


class Event(object):
    _observers = {}
    _event_subjects = []

    def __init__(self, subject, event_param):
        self.subject = subject
        self.param = event_param

    @classmethod
    def register(cls, event_subject, observer):
        if event_subject not in cls._event_subjects:
            cls._event_subjects.append(event_subject)
            cls._observers[event_subject] = []
        if observer not in cls._observers[event_subject]:
            cls._observers[event_subject].append(observer)

    @classmethod
    def unregister(cls, event_subject, observer):
        if event_subject not in cls._event_subjects:
            return None
        if observer in cls._observers[event_subject]:
            cls._observers.remove(observer)
        if len(cls._observers[event_subject]) == 0:
            del cls._observers[event_subject]
            cls._event_subjects.remove(event_subject)

    @classmethod
    def notify(cls, subject, event_param):
        if subject not in cls._event_subjects:
            return None
        event = Event(subject, event_param)
        for observer in cls._observers[subject]:
            observer(event)


class ChangePacketDataEventHandle(object):

    def __init__(self, subject, effect_obj):
        self.position = -1
        self.operator = None
        self.data = None
        self.subject = subject
        self.obj = effect_obj

    def set_operate_type(self, byte_position, operator, operate_data):
        self.position = byte_position
        self.operator = operator
        self.data = operate_data

    def filter_event_condition(self, strdata):
        global CHANGE_DATA_COUNT, GLOBAL_COUNT_INDEX
        ret_val = False
        if CHANGE_DATA_COUNT == 0:
            CHANGE_DATA_COUNT = random.randint(1, 100)
        if CHANGE_DATA_NOT_RANDOM:
            self.set_operate_type(CHANGE_DATA_POSITION, CHANGE_DATA_OPERATOR, CHANGE_DATA_OPERATE_DATA)
            if len(CHANGE_DATA_CONTAIN) > 0:
                for tmp_contain in CHANGE_DATA_CONTAIN:
                    if strdata.find(tmp_contain) > -1:
                        GLOBAL_COUNT_INDEX += 1
                        break
            else:
                GLOBAL_COUNT_INDEX += 1
            if GLOBAL_COUNT_INDEX == CHANGE_DATA_COUNT:
                ret_val = True
                GLOBAL_COUNT_INDEX = 0
        else:
            if len(CHANGE_DATA_CONTAIN) > 0:
                for tmp_contain in CHANGE_DATA_CONTAIN:
                    if strdata.find(tmp_contain) > -1:
                        GLOBAL_COUNT_INDEX += 1
                        break
            else:
                GLOBAL_COUNT_INDEX += 1
            if GLOBAL_COUNT_INDEX == CHANGE_DATA_COUNT:
                if CHANGE_DATA_POSITION == 0:
                    tmp_position = random.randint(1, len(strdata) / 2)
                else:
                    tmp_position = CHANGE_DATA_POSITION
                tmp_operator = random.choice(("&", "|", "^"))
                tmp_operate_data = random.randint(1, 255)
                self.set_operate_type(tmp_position, tmp_operator, tmp_operate_data)
                ret_val = True
                GLOBAL_COUNT_INDEX = 0
        return ret_val

    def event_handle(self, event):
        ret_data = event.param.data.data
        if self.filter_event_condition(binascii.b2a_hex(ret_data)):
            tmp_index = -1
            data_array = bytes(ret_data)
            if self.position > 0:
                if self.position <= len(data_array):
                    tmp_index = self.position - 1
                    tmp_data = data_array[tmp_index]
            else:
                if abs(self.position) <= len(data_array):
                    tmp_index = len(data_array) + self.position
                    tmp_data = data_array[tmp_index]
            if self.operator == "&" and tmp_index > -1 and self.subject == event.subject:
                tmp_data = struct.pack("!B", int(binascii.b2a_hex(tmp_data), 16) & self.data)
                ret_data = ret_data[:tmp_index] + tmp_data + ret_data[tmp_index+1:]
            elif self.operator == "|" and tmp_index > -1 and self.subject == event.subject:
                tmp_data = struct.pack("!B", int(binascii.b2a_hex(tmp_data), 16) | self.data)
                ret_data = ret_data[:tmp_index] + tmp_data + ret_data[tmp_index+1:]
            elif self.operator == "^" and tmp_index > -1 and self.subject == event.subject:
                tmp_data = struct.pack("!B", int(binascii.b2a_hex(tmp_data), 16) ^ self.data)
                ret_data = ret_data[:tmp_index] + tmp_data + ret_data[tmp_index+1:]
        self.obj.t_data = ret_data


class PacketInfo(Event):

    def __init__(self, threadname, srcip, dstip, mockip, srcport, dstport, mockport):
        self.src_ip = srcip
        self.dst_ip = dstip
        self.mock_ip = mockip
        self.src_port = srcport
        self.dst_port = dstport
        self.mock_port = mockport
        self.thread_name = threadname
        self.t_data = None
        self.set_change_data_event()

    def packet_sniffer(self, sniffer_card, is_source):
        global GLOBAL_IS_EXIT
        pc = pcapy.open_live(sniffer_card, 10240, True, 2000)
        while True:
            try:
                if GLOBAL_IS_EXIT:
                    print "exit thread loop... sub process %s will be exit." % threading.currentThread().getName()
                    break
                packet_time, packet_data = pc.next()
                target_data = self.filter_packet(packet_time, packet_data, is_source)
                if target_data is not None:
                    if CHANGE_DATA_EVENT:
                        self.notify("change_packet_data_%s" % self.thread_name, target_data)
                    self.forward_packet(target_data)
            except:
                continue

    def filter_packet(self, p_time, p_data, is_source):
        unpack_data = dpkt.ethernet.Ethernet(p_data)
        if is_source:
            ip_info = tuple(map(ord, list(unpack_data.data.src)))
            target_ip = self.src_ip
        else:
            ip_info = tuple(map(ord, list(unpack_data.data.dst)))
            target_ip = self.dst_ip
        if len(ip_info) != 4:
            return None
        t_ip = '%d.%d.%d.%d' % ip_info
        if t_ip.find(target_ip) > -1:
            return unpack_data.data
        else:
            return None

    def set_change_data_event(self):
        event_handle_obj = ChangePacketDataEventHandle("change_packet_data_%s" % self.thread_name, self)
        self.register("change_packet_data_%s" % self.thread_name, event_handle_obj.event_handle)

    def forward_packet(self, target_data):
        if self.t_data is None:
            print "change data error ......"
            self.t_data = target_data.data.data
        mock_packet = IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=self.src_port,
                                                                 dport=self.dst_port) / self.t_data
        send(mock_packet)
        self.t_data = None

    def get_log_time(self):
        temp_timestamp = time.time()
        ret_str = time.strftime("%H:%M:%S", time.localtime(temp_timestamp))
        ret_str += str("%.3f" % temp_timestamp)[-4:]
        return int(temp_timestamp*1000), ret_str


class ForwardToInside(PacketInfo):

    def __init__(self, nattype, threadname, srcip, dstip, mockip, srcport, dstport, mockport):
        super(ForwardToInside, self).__init__(threadname, srcip, dstip, mockip, srcport, dstport, mockport)
        self.nat_type = nattype
        self.protocol_type = 0

    def run_task(self):
        self.packet_sniffer(PUB_NET_CARD, False)

    def filter_packet(self, p_time, p_data, is_source):
        need_forward = False
        unpack_data = dpkt.ethernet.Ethernet(p_data)
        # if unpack_data.data.p != 17 and unpack_data.data.p != 6:
        if unpack_data.data.p != 17:
            return None
        self.protocol_type = unpack_data.data.p
        ip_sinfo = tuple(map(ord, list(unpack_data.data.src)))
        ip_dinfo = tuple(map(ord, list(unpack_data.data.dst)))
        if len(ip_sinfo) != 4 or len(ip_dinfo) != 4:
            return None
        srcip = '%d.%d.%d.%d' % ip_sinfo
        dstip = '%d.%d.%d.%d' % ip_dinfo
        dstport = unpack_data.data.data.dport
        srcport = unpack_data.data.data.sport
        if self.nat_type == "1":
            if dstip == self.dst_ip and dstport == self.dst_port:
                need_forward = True
        elif self.nat_type == "2":
            if dstip == self.dst_ip and dstport == self.dst_port and \
                            srcip in NAT_ROUTE_DICT[(self.mock_ip, self.mock_port)]:
                need_forward = True
        elif self.nat_type == "3":
            if dstip == self.dst_ip and dstport == self.dst_port and \
                            (srcip, srcport) in NAT_ROUTE_DICT[(self.mock_ip, self.mock_port)]:
                need_forward = True
        elif self.nat_type == "3.5":
            if dstip == self.dst_ip and dstport == self.dst_port and \
                            (srcip, srcport) in NAT_ROUTE_DICT[(self.mock_ip, self.mock_port, srcip)]:
                need_forward = True
        elif self.nat_type == "4":
            if dstip == self.dst_ip and dstport == self.dst_port and \
                            (srcip, srcport) in NAT_ROUTE_DICT[(self.mock_ip, self.mock_port, srcip, srcport)]:
                need_forward = True
        else:
            raise Exception("Unsupport nat_type: " % self.nat_type)
        if need_forward:
            self.src_ip = srcip
            self.src_port = srcport
            return unpack_data.data
        else:
            return None

    def forward_packet(self, target_data):
        if self.t_data is None:
            if CHANGE_DATA_EVENT:
                print "no change data, send original data ......"
            self.t_data = target_data.data.data
        if self.protocol_type == 17:
            tmp_protocol_str = "UDP"
            mock_packet = IP(src=self.src_ip, dst=self.mock_ip) / UDP(sport=self.src_port,
                                                                      dport=self.mock_port) / self.t_data
        elif self.protocol_type == 6:
            tmp_protocol_str = "TCP"
            mock_packet = IP(src=self.src_ip, dst=self.mock_ip) / TCP(sport=self.src_port,
                                                                      dport=self.mock_port) / target_data.data.data
        send(mock_packet)
        log_str = "%s log[protocl: %s]: forward to INside(src: (%s, %s)): (%s, %s) --> (%s, %s), packet: %s " \
                  "[after: %s]" % (self.get_log_time()[1], tmp_protocol_str, self.dst_ip, str(self.dst_port),
                                   self.src_ip, str(self.src_port), self.mock_ip, str(self.mock_port),
                                   binascii.b2a_hex(target_data.data.data), binascii.b2a_hex(self.t_data))
        print log_str
        LOG_FILE_HANDLE.write(log_str + "\n")
        LOG_FILE_HANDLE.flush()
        if log_str.find("packet: a1") > -1 or log_str.find("packet: d1") > -1:
            LOG_FILE_PENETRATOR.write(log_str + "\n")
            LOG_FILE_PENETRATOR.flush()
        self.t_data = None


class ForwardToOutside(PacketInfo):

    thread_name_index = 1

    def __init__(self, nattype, threadname, srcip, dstip, mockip, srcport, dstport, mockport):
        super(ForwardToOutside, self).__init__(threadname, srcip, dstip, mockip, srcport, dstport, mockport)
        self.nat_type = nattype
        self.protocol_type = 0
        self.out_in_route = {}
        self.mock_ports = []
        self.nat_mapping_list = []

    def run_task(self):
        self.packet_sniffer(PRI_NET_CARD, True)

    def filter_packet(self, p_time, p_data, is_source):
        if PRI_NET_MOLD == "ETH":
            unpack_data = dpkt.ethernet.Ethernet(p_data)
        elif PRI_NET_MOLD == "PPP":
            unpack_data = dpkt.ethernet.Ethernet(p_data[2:])
        else:
            raise Exception("Unsupport PRI_NET_MOLD type: %s" % PRI_NET_MOLD)
        # if unpack_data.data.p != 17 and unpack_data.data.p != 6:
        if unpack_data.data.p != 17:
            return None
        self.protocol_type = unpack_data.data.p
        ip_sinfo = tuple(map(ord, list(unpack_data.data.src)))
        ip_dinfo = tuple(map(ord, list(unpack_data.data.dst)))
        if len(ip_sinfo) != 4 or len(ip_dinfo) != 4:
            return None
        srcip = '%d.%d.%d.%d' % ip_sinfo
        dstip = '%d.%d.%d.%d' % ip_dinfo
        dstport = unpack_data.data.data.dport
        srcport = unpack_data.data.data.sport
        if srcip.find(self.src_ip) > -1 and dstip.find(self.src_ip) == -1 and srcport > 9999 and dstip != "224.0.0.252":
            self.src_ip = srcip
            self.dst_ip = dstip
            self.dst_port = dstport
            self.src_port = srcport
            if self.nat_type == "1" or self.nat_type == "2" or self.nat_type == "3":
                temp_mapping_key = (srcip, srcport)
            elif self.nat_type == "3.5":
                temp_mapping_key = (srcip, srcport, dstip)
            elif self.nat_type == "4":
                temp_mapping_key = (srcip, srcport, dstip, dstport)
            else:
                raise Exception("Unsupport nat_type: %s" % self.nat_type)
            if temp_mapping_key not in NAT_ROUTE_DICT.keys():
                NAT_ROUTE_DICT[temp_mapping_key] = []
            if self.nat_type == "2":
                if dstip not in NAT_ROUTE_DICT[temp_mapping_key]:
                    NAT_ROUTE_DICT[temp_mapping_key].append(dstip)
            elif self.nat_type == "3" or self.nat_type == "3.5" or self.nat_type == "4":
                if (dstip, dstport) not in NAT_ROUTE_DICT[temp_mapping_key]:
                    NAT_ROUTE_DICT[temp_mapping_key].append((dstip, dstport))
            temp_tuple_key = (dstip, self.mock_ip, srcip, dstport, self.mock_port, srcport)
            if temp_tuple_key not in self.out_in_route.keys():
                if temp_mapping_key not in self.nat_mapping_list:
                    if self.nat_type == "4":
                        if self.mock_port in self.mock_ports:
                            self.mock_port = self.mock_ports[len(self.mock_ports) - 1] + 1
                            self.mock_ports.append(self.mock_port)
                            temp_tuple_key = (dstip, self.mock_ip, srcip, dstport, self.mock_port, srcport)
                        else:
                            self.mock_ports.append(self.mock_port)
                    self.out_in_route[(dstip, self.mock_ip, srcip, dstport, self.mock_port, srcport)] = p_time
                    self.nat_mapping_list.append(temp_mapping_key)
                    thread_name = "in_forward_" + str(self.__class__.thread_name_index)
                    self.__class__.thread_name_index += 1
                    temp_in_bridge = ForwardToInside(self.nat_type, thread_name, *temp_tuple_key)
                    temp_in_thread = threading.Thread(target=temp_in_bridge.run_task, name=temp_in_bridge.thread_name)
                    temp_in_thread.setDaemon(True)
                    temp_in_thread.start()
                    GLOBAL_THREAD_POOL.append(temp_in_thread)
                    log_str = "%s log: create OUT_TO_IN tunnel thread, info: %s ." % (
                        self.get_log_time()[1], ", ".join([str(x) for x in temp_tuple_key]))
                    print log_str
                    LOG_FILE_HANDLE.write(log_str + "\n")
                    LOG_FILE_HANDLE.flush()
            return unpack_data.data
        else:
            return None

    def forward_packet(self, target_data):
        if self.t_data is None:
            if CHANGE_DATA_EVENT:
                print "no change data, send original data ......"
            self.t_data = target_data.data.data
        if self.protocol_type == 17:
            tmp_protocol_str = "UDP"
            mock_packet = IP(src=self.mock_ip, dst=self.dst_ip) / UDP(sport=self.mock_port,
                                                                 dport=self.dst_port) / self.t_data
        elif self.protocol_type == 6:
            tmp_protocol_str = "TCP"
            mock_packet = IP(src=self.mock_ip, dst=self.dst_ip) / TCP(sport=self.mock_port,
                                                                      dport=self.dst_port) / target_data.data.data
        send(mock_packet)
        log_str = "%s log[protocl: %s]: forward to OUTside(src: (%s, %s)): (%s, %s) --> (%s, %s), packet: %s " \
                  "[after: %s]" % (self.get_log_time()[1], tmp_protocol_str, self.dst_ip, str(self.dst_port),
                                   self.src_ip, str(self.src_port), self.mock_ip, str(self.mock_port),
                                   binascii.b2a_hex(target_data.data.data), binascii.b2a_hex(self.t_data))
        print log_str
        LOG_FILE_HANDLE.write(log_str + "\n")
        LOG_FILE_HANDLE.flush()
        if log_str.find("packet: a1") > -1 or log_str.find("packet: d1") > -1:
            LOG_FILE_PENETRATOR.write(log_str + "\n")
            LOG_FILE_PENETRATOR.flush()
        self.t_data = None


def dummy_nat(type_number):
    thread_name = "out_forward_0"
    out_bridgehead = ForwardToOutside(type_number, thread_name, PRI_NET_RANGE, "", PUB_GW_HOST_IP, 0, 0, MOCK_GW_PORT)
    out_thread = threading.Thread(target=out_bridgehead.run_task, name=out_bridgehead.thread_name)
    out_thread.setDaemon(True)
    out_thread.start()
    GLOBAL_THREAD_POOL.append(out_thread)
    return out_thread


def _nat_conf_init():
    global PRI_NET_RANGE, PRI_NET_CARD, PRI_NET_MOLD, PUB_NET_CARD, PUB_GW_HOST_IP, DUMMY_NAT_TYPE, MOCK_GW_PORT
    global CHANGE_DATA_EVENT, CHANGE_DATA_NOT_RANDOM, CHANGE_DATA_POSITION, CHANGE_DATA_OPERATOR, \
        CHANGE_DATA_OPERATE_DATA, CHANGE_DATA_COUNT, CHANGE_DATA_CONTAIN
    global LOG_FILE_HANDLE, LOG_FILE_PENETRATOR
    yml_file = open("natconfig.yaml", "r")
    conf_info = yaml.load(yml_file)
    PRI_NET_RANGE = conf_info["PRI_NET_RANGE"]
    PRI_NET_CARD = conf_info["PRI_NET_CARD"]
    PRI_NET_MOLD = conf_info["PRI_NET_MOLD"]
    PUB_NET_CARD = conf_info["PUB_NET_CARD"]
    PUB_GW_HOST_IP = conf_info["PUB_GW_HOST_IP"]
    MOCK_GW_PORT = conf_info["MOCK_GW_PORT"]
    DUMMY_NAT_TYPE = conf_info["DUMMY_NAT_TYPE"]
    # FILTER_PROTOCOL_TYPE = conf_info["FILTER_PROTOCOL_TYPE"]
    CHANGE_DATA_EVENT = conf_info["CHANGE_DATA_EVENT"]
    CHANGE_DATA_NOT_RANDOM = conf_info["CHANGE_DATA_NOT_RANDOM"]
    CHANGE_DATA_POSITION = conf_info["CHANGE_DATA_POSITION"]
    CHANGE_DATA_OPERATOR = conf_info["CHANGE_DATA_OPERATOR"]
    CHANGE_DATA_OPERATE_DATA = conf_info["CHANGE_DATA_OPERATE_DATA"]
    CHANGE_DATA_COUNT = conf_info["CHANGE_DATA_COUNT"]
    CHANGE_DATA_CONTAIN = conf_info["CHANGE_DATA_CONTAIN"]
    log_file_path = "./log"
    log_file_file = "forward_%s" % str(int(time.time()))
    if not os.path.isdir(log_file_path):
        os.mkdir(log_file_path)
    LOG_FILE_HANDLE = open(os.path.join(log_file_path, log_file_file), "w")
    LOG_FILE_PENETRATOR = open(log_file_path + "/penetrator.log", "w")


def sig_handler(signum, frame):
    global GLOBAL_IS_EXIT
    if not GLOBAL_IS_EXIT:
        print "process begin to exit, please wait ..."
    GLOBAL_IS_EXIT = True


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTSTP, sig_handler)
    _nat_conf_init()
    index_list = []
    if len(sys.argv) > 1:
        t_num = sys.argv[1]
    else:
        t_num = DUMMY_NAT_TYPE
    try:
        dummy_nat(t_num)
        while len(GLOBAL_THREAD_POOL) > 0:
            time.sleep(3)
            for i in range(len(GLOBAL_THREAD_POOL)):
                if not GLOBAL_THREAD_POOL[i].isAlive():
                    index_list.append(i)
            index_list.reverse()
            for j in index_list:
                del GLOBAL_THREAD_POOL[j]
            del index_list[:]
    except KeyboardInterrupt:
        stop_command = "ps -ef | grep %s | grep -v grep | cut -c 9-15 | xargs kill -s 9" % os.path.basename(__file__)
        os.system(stop_command)
    except Exception, e:
        print "exception in running, error message: %s ." % e.message
    finally:
        if LOG_FILE_HANDLE is not None:
            LOG_FILE_HANDLE.close()
        if LOG_FILE_PENETRATOR is not None:
            LOG_FILE_PENETRATOR.close()
    print "the process exit finish..."
