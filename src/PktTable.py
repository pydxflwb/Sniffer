from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from scapy.all import *
import sys,time
import SnifferThread
global pkt_label
pkt_label= ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']

def GetInfo(pkt:Packet):
    PktSummary = pkt.summary()
    PktSumList = PktSummary.split("/")
    try:
        if "Ether" in PktSumList[0]:
            prtcl = SnifferThread.GetProtocol(pkt)
            if "ARP" in prtcl:
                ARPInfo = PktSumList[1].strip().split(' ')[1:]
                if ARPInfo[0] == 'who' and ARPInfo[1] == 'has':
                    Info = "Who has "+ARPInfo[2]+" ? Tell "+ARPInfo[4]
                elif ARPInfo[0] == 'is' and ARPInfo[1] == 'at':
                    Info = ARPInfo[4]+" is at "+ARPInfo[2]
                else:
                    Info = PktSumList[1].strip()
            elif "DNS" in prtcl:
                Info = PktSumList[-1]
            elif "TCP" in prtcl or "UDP" in prtcl:
                IpList = PktSumList[2:]
                Info = ""
                for str in IpList:
                    Info = Info + str
            else:
                IpList = PktSumList[1:]
                Info = ""
                for str in IpList:
                    Info = Info + str
            return Info
        else:
            return PktSummary
    except:
        return PktSummary

def BuildPktDict(No, StartTime, pkt:Packet):
    pkt_information = {
        'No.' : str(No),
        'Time': str(pkt.time - StartTime)[0:9],
        'Protocol' : SnifferThread.GetProtocol(pkt),
        'Length' : str(len(pkt)),
        'Info' : GetInfo(pkt),
    }
    if StartTime == 0:
        #Time = time.time()
        pkt_information['Time'] = str(float(pkt.time)-float(time.time()))[0:10]
    pkt_information['Source'], pkt_information['Destination'] = SnifferThread.SrcAndDst(pkt)
    return pkt_information

def SetRowColor(proto: str):
    if 'TCP' in proto:
        color = QColor('#4dffff')
    elif 'UDP' in proto:
        color = QColor('#7afec6')
    elif 'ICMP' in proto:
        color = QColor('#ff79bc')
    elif 'ARP' in proto:
        color = QColor('#ea7500')
    elif 'DHCP' in proto:
        color = QColor('#c4c400')
    elif 'DNS' in proto:
        color = QColor('#d63b2d')
    else:
        color = QColor('#9f4d95')
    return color

class PktTable(QWidget):
    #Signal_DoubleClicked = pyqtSignal(int)
    def __init__(self):
        super(PktTable, self).__init__()
        self.initUI()

    def initUI(self):
        self.layout = QHBoxLayout()
        self.auto_scroll = True
        self.tablewidget = QTableWidget()
        self.tablewidget.setColumnCount(7)
        #表头
        self.tablewidget.setHorizontalHeaderLabels(pkt_label)
        self.tablewidget.horizontalHeader().setStyleSheet("QHeaderView::section{background-color:#9FE888;}")
        # 水平方向表格自适应伸缩
        self.tablewidget.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive) #ResizeToContents
        #表格禁止编辑
        self.tablewidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        #选择行
        self.tablewidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        #最后一列决定充满剩下的界面
        self.tablewidget.horizontalHeader().setStretchLastSection(True)
        #隐藏列首，虽然没有设置，但是会自动出来一个
        self.tablewidget.verticalHeader().setVisible(False)
        #将行与列的高度设置为所显示的内容的宽度高度匹配
        QTableWidget.resizeColumnsToContents(self.tablewidget)
        QTableWidget.resizeRowsToContents(self.tablewidget)

        #self.tablewidget.cellDoubleClicked.connect(self.DoubleClick)

        self.layout.addWidget(self.tablewidget)
        self.setLayout(self.layout)

    # Insert Operations
    def InsertNewRow(self, row_num, pkt_information):
        for i in range(len(pkt_label)):
            temp = QTableWidgetItem(pkt_information[pkt_label[i]])
            color = SetRowColor(pkt_information['Protocol'])
            temp.setBackground(color)
            self.tablewidget.setItem(row_num, i, temp)
        if self.auto_scroll:
            self.tablewidget.scrollToBottom()

    def InsertPkt(self, pkt_information):
        row_num = self.tablewidget.rowCount()  
        self.tablewidget.insertRow(row_num)
        self.InsertNewRow(row_num, pkt_information)
        return row_num

    def InsertRowByIndex(self, index, pkt_information):
        row_num = self.tablewidget.rowCount()
        if index >= row_num:
            self.tablewidget.setRowCount(index+1)
        self.InsertNewRow(index, pkt_information)

    def SetAutoScroll(self, state):
        self.auto_scroll = state

    def clear(self):
        self.tablewidget.clear()
        self.tablewidget.setRowCount(0)
        self.tablewidget.setHorizontalHeaderLabels(pkt_label)

    #def DoubleClick(self):
    #   self.Signal_DoubleClick.emit()
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    pkt_table = PktTable()
    pkt_table.show()
    sys.exit(app.exec_())
