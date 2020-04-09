from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from scapy.all import *
from contextlib import redirect_stdout
import sys, io, time
import scapy.all as Scp

import SnifferThread
import PktTable 

global pkt_label
pkt_label= ['No.' , 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']

class TabBar(QTabBar):
    def tabSizeHint(self, index):
        s = QtWidgets.QTabBar.tabSizeHint(self, index)
        s.transpose()
        return s

    def paintEvent(self, event):
        painter = QtWidgets.QStylePainter(self)
        opt = QtWidgets.QStyleOptionTab()

        for i in range(self.count()):
            self.initStyleOption(opt, i)
            painter.drawControl(QtWidgets.QStyle.CE_TabBarTabShape, opt)
            painter.save()

            s = opt.rect.size()
            s.transpose()
            r = QtCore.QRect(QtCore.QPoint(), s)
            r.moveCenter(opt.rect.center())
            opt.rect = r

            c = self.tabRect(i).center()
            painter.translate(c)
            painter.rotate(90)
            painter.translate(-c)
            painter.drawControl(QtWidgets.QStyle.CE_TabBarTabLabel, opt);
            painter.restore()


class ResultTable(QWidget):
    def __init__(self):
        super(ResultTable, self).__init__()
        self.initUI()

    def initUI(self):
        self.layout = QHBoxLayout()
        self.tabwidget = QTabWidget()
        self.font = QFont("Roman times", 10, QFont.Bold)

        self.Ethernet_detail = QTextBrowser()
        self.Ethernet_detail.setFont(self.font)

        self.IP_detail = QTextBrowser()
        self.IP_detail.setFont(self.font)

        self.Protocol_detail = QTextBrowser()
        self.Protocol_detail.setFont(self.font)

        self.hex_detail = QTextBrowser()
        self.hex_detail.setFont(self.font)

        #self.detail = QScrollArea()

        self.tabwidget.setTabBar(TabBar())
        self.tabwidget.setTabPosition(QTabWidget.West)
        self.tabwidget.addTab(self.Ethernet_detail, "Ethernet")
        self.tabwidget.addTab(self.IP_detail, "IP")
        self.tabwidget.addTab(self.Protocol_detail, "Protocol")
        self.tabwidget.addTab(self.hex_detail, "Hex Info")
        #self.tabwidget.addTab(self.detail, "Detail")
        self.tabwidget.setStyleSheet("""QTabBar::tab {font-family:'Roman times'; min-height:120px; min-width: 30px;}
                                QTabBar::tab:selected {font-family:'Roman times';font-weight:bold;font-size: 18px}
                                QTabBar::tab:hover {color: grey }
                            """)

        self.layout.addWidget(self.tabwidget)
        self.setLayout(self.layout)

    def ShowDetail(self, pkt: Packet):
        prtcl = SnifferThread.GetProtocol(pkt)
        with io.StringIO() as buf, redirect_stdout(buf):
            Scp.hexdump(pkt)
            hex_packet = buf.getvalue()
        self.hex_detail.setText(hex_packet)
        with io.StringIO() as buf, redirect_stdout(buf):
            pkt[0].show()
            Ethernet_analysis = buf.getvalue()
        self.Ethernet_detail.setText(Ethernet_analysis)
        with io.StringIO() as buf, redirect_stdout(buf):
            pkt[1].show()
            IP_analysis = buf.getvalue()
        temp_IPdetail = IP_analysis
        self.IP_detail.setText(IP_analysis)

        try:
            with io.StringIO() as buf, redirect_stdout(buf):
                pkt[2].show()
                Protocol_analysis = buf.getvalue()
            self.Protocol_detail.setText(Protocol_analysis)
        except:
            self.IP_detail.setText("")
            self.Protocol_detail.setText(temp_IPdetail)
        #print(str(pkt[Raw].load))
        #print(str(pkt[Raw].load)[0])

    def clear(self):
        self.Ethernet_detail.setText("")
        self.IP_detail.setText("")
        self.Protocol_detail.setText("")
        self.hex_detail.setText("")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    result_table = ResultTable()
    result_table.show()
    sys.exit(app.exec_())
