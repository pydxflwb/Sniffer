from scapy.all import *
from PyQt5 import QtCore
import threading

def GetProtocol(pkt:Packet):
    PktSummary = pkt.summary()
    PktSumList = PktSummary.split("/")
    ProtocolList1 = ['ARP','RARP','DHCP']
    for prtcl in ProtocolList1:
        if prtcl in PktSumList[1]:
            return prtcl
    if 'IPv6' in PktSumList[1]:
    #eg. Ether / IPv6 / UDP fe80::c14c:d0f3:10a:92de:64073 > ff02::1:3:llmnr / LLMNRQuery
        return 'IPv6/'+PktSumList[2].strip().split(' ')[0]
    elif 'IP' in PktSumList[1]:
    #eg. Ether / IP / TCP 182.61.200.129:https > 192.168.1.109:62028 PA / Raw
        if 'Raw' in PktSumList[-1] or 'Padding' in PktSumList[-1]:
            UpperPrtcl = PktSumList[-2]
        else:
            UpperPrtcl = PktSumList[-1]
        return UpperPrtcl.strip().split(' ')[0]
    else:
        Prtcl = PktSumList[2].split(' ')[0].strip()
        if Prtcl != '':
            Prtcl = Prtcl+'/'
        Prtcl=Prtcl+PktSumList[2].split(' ')[1]
        return Prtcl

def SrcAndDst(pkt):
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
    except:
        src = pkt[0].src
        dst = pkt[0].dst
    return src, dst

def Reassemble_packet(plist):
    id_dict = {}
    for pkt in plist:
        if str(pkt[IP].id) not in id_dict.keys():
            id_dict[str(pkt[IP].id)] = PacketList()
            id_dict[str(pkt[IP].id)].append(pkt)
        else:
            id_dict[str(pkt[IP].id)].append(pkt)

    result_dict = {}
    for id_key in id_dict.keys():
        tmp_dict = {}
        for pkt in id_dict[id_key]:
            tmp_dict[str(pkt[IP].frag)] = pkt
        try:
            result_dict[id_key] = tmp_dict['0']
        except:
            return None
        loads = b''
        for frag in sorted(tmp_dict.keys()):
            loads = loads + tmp_dict[frag].getlayer(Raw).load

        result_dict[id_key].len += len(loads) - len(result_dict[id_key][Raw].load)
        result_dict[id_key][Raw].load = loads
        result_dict[id_key].flags = 2
        result_dict[id_key].frag = 0
    return result_dict

class SnifferThread(QtCore.QThread):

    Signal_UpdateShow = QtCore.pyqtSignal(int, Packet)
    
    def __init__(self, Signal_SniffStop = None, Interf = None, PktCount = 0, Filter = None, *args, **kwargs):

        super(SnifferThread, self).__init__()

        self.SniffPkt = None
        self.Interf = Interf
        self.Filter = Filter
        self.PktCount = PktCount
        
        self.SniffPkt = None        
        self.Event_Stop = threading.Event()     # To Block Other Threadings
        self.Signal_SniffStop = Signal_SniffStop
        self.Signal_SniffStop.connect(self.join)# Signal Connect to Function

    def run(self):
        print("### Sniffer ###")
        self.SniffPkt = sniff(iface= self.Interf, filter= self.Filter,
                              prn= self.Callback, stop_filter=lambda p: self.Event_Stop.is_set())
        print("### Sniffer Stop###")

    # Redefine Functions
    def join(self,Flag_Stop):     
        if(Flag_Stop):
            self.Event_Stop.set()   # Set False
            print("### Sniffer Stop -- ThreadID: %d ###"%self.currentThreadId())



    def Callback(self, pkt:Packet):
        self.PktCount += 1
        self.Signal_UpdateShow.emit(self.PktCount, pkt)
    
