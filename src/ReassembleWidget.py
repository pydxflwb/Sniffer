from PyQt5.QtCore import QSize, pyqtSignal
from PyQt5.QtWidgets import *
from scapy.all import *
from contextlib import redirect_stdout
import sys, io, time
import scapy.all as Scp
import PktTable
global pkt_label
pkt_label= ['No.' , 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']

class ReassembleWidget(QWidget):

    Signal_Reass = pyqtSignal(Packet)

    def __init__(self):
        super(ReassembleWidget, self).__init__()
        self.initUI()

    def sizeHint(self):
        return QSize(700,300)

    def initUI(self):
        self.layout = QHBoxLayout()
        self.reasstbl = PktTable.PktTable()
        self.reasstbl.tablewidget.horizontalHeader().setStyleSheet("QHeaderView::section{background-color:#7AA8D9;}")
        self.reasstbl.tablewidget.cellDoubleClicked.connect(self.ReassembleClick)
        self.reassemble_dict = {}
        self.layout.addWidget(self.reasstbl)
        self.setLayout(self.layout)
        self.setGeometry(300, 100, 900, 400)

    def clear(self):
        self.reasstbl.clear()

    def UpdateReassemble(self, StartTime, Pdict):
        self.reassemble_dict = {}
        self.reasstbl.clear()
        for key in Pdict.keys():
            pkt_information = PktTable.BuildPktDict(len(self.reassemble_dict), StartTime, Pdict[key])
            row_num = self.reasstbl.InsertPkt(pkt_information)
            self.reassemble_dict[str(row_num)] = Pdict[key]
        #self.reassemble.adjust_RowHeader()

    def ReassembleClick(self, row):
        if str(row) in self.reassemble_dict.keys():
            pkt = self.reassemble_dict[str(row)]
            self.Signal_Reass.emit(pkt)
            #self.ShowDetail(pkt)  ########## Here to Change
        else:
            self.reasstbl.clear()