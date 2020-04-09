import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
import PktTable
import InterfaceBox
import SnifferThread
from scapy.all import *

global pkt_label
pkt_label= ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']

class CentralWidget(QWidget):
    Signal_SniffStop_Interf = pyqtSignal(bool)
    def __init__(self):
        super().__init__()
        self.Interf = ' '
        self.initUI()

    def initUI(self):
        # Layout
        self.Tool_hbox = QHBoxLayout()
        self.overall_vbox = QVBoxLayout()

        # InterfBox
        self.InterfBox = InterfaceBox.InterfaceBox()
        self.Signal_Interf = self.InterfBox.Signal_InterfSet
        self.Signal_Interf.connect(self.InterfWarning) 
        # Search
        self.Label_Search = QLabel("Search")
        self.Label_Search.setFont(QFont("Myriad Pro", 12))
        self.text = QLineEdit(self)
        self.search = QPushButton("Go")
        self.search.setFont(QFont("Myriad Pro",10))
        # Central Boxes
        self.pkt_table = PktTable.PktTable()
        self.pkt_table_cellClicked = self.pkt_table.tablewidget.cellDoubleClicked

        # This Widget now is changed into a dockwidget in MainWindow, so we do not use it
        #self.result_table = ResultTable.ResultTable()

        # Create Real Object to Build Window
        self.Tool_hbox.addWidget(self.InterfBox)
        #self.Tool_hbox.addStretch(1)#控制间隔
        self.Tool_hbox.addWidget(self.Label_Search)
        self.Tool_hbox.addWidget(self.text)
        self.Tool_hbox.addWidget(self.search)
    
        self.tmp_widget = QWidget()
        self.tmp_widget.setLayout(self.Tool_hbox)

        self.overall_vbox.addWidget(self.tmp_widget)
        self.overall_vbox.addWidget(self.pkt_table.tablewidget)
        #self.overall_vbox.addWidget(self.result_table.tabwidget)

        self.setLayout(self.overall_vbox)

    # Functions

    # InterfaceBox
    def InterfWarning(self):
        Reply = QMessageBox.question(self, 'Change Interface ?',
            "You are trying to change interface.\nThis action will clear the table.\n\tContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No )
        if Reply == QMessageBox.Yes:
            self.Interf = self.InterfBox.InterfChose
            print(self.Interf)
            self.Signal_SniffStop_Interf.emit(True)
        else:
            self.InterfBox.Flag_Interf = False
            self.InterfBox.BacktoOldInterf(self.Interf)
            print(self.InterfBox.InterfChose)

    def SetAutoScroll(self, state):
        self.pkt_table.SetAutoScroll(state)

    def Search(self):
        return self.text.text()

    def PktTableClear(self):
        self.pkt_table.clear()

    def InsertPkt(self, pkt_information):
        return self.pkt_table.InsertPkt(pkt_information) 

    def InsertRowByIndex(self, index, pkt_information):
        self.pkt_table.InsertRowByIndex(index, pkt_information)

    def BuildPktDict(self, No,StartTime, pkt):
        return PktTable.BuildPktDict(No, StartTime, pkt)

    def UpdatePacketTable(self, No, StartTime, pkt):
        #prtcl=SnifferThread.GetProtocol(pkt)
        SingleRow = self.BuildPktDict(No, StartTime, pkt)
        RowNum = self.InsertPkt(SingleRow)
        return RowNum


    
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CentralWidget()
    win.setGeometry(300, 100, 1000, 800)
    win.show()
    sys.exit(app.exec_())
