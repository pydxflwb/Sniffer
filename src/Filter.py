import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from scapy.all import *

class EmptyDelegate(QItemDelegate):
    def __init__(self, parent):
        super(EmptyDelegate, self).__init__(parent)

    def createEditor(self, QWidget, QStyleOptionViewItem, QModelIndex):
        return None

class Filter(QWidget):
    filter_emit = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.initUI()

    def sizeHint(self):
        return QSize(500,500)

    def initUI(self):
        self.filter = {
            'host': "[src or dst] host <ip>",
            'port': "[src or dst] port <port>",
            'proto': "[ip or ip6][src or dst] proto <protocol>",
            'ether host': "ether [src or dst] host <ip>",
            'net': "[src or dst] net <net>",
            'gateway': "gateway <ip>",
            'mask' : "net <net> mask <mask>",
            'vlan': "vlan <ID>"
        }

        self.rule = ''

        #self.setWindowTitle("Filter")

        self.layout = QVBoxLayout()

        self.filter_table = QTableWidget(8, 3)
        self.filter_table.setHorizontalHeaderLabels(["名称", "格式", "过滤器"])
        self.filter_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.filter_table.verticalHeader().setVisible(False)
        QTableWidget.resizeColumnsToContents(self.filter_table)
        QTableWidget.resizeRowsToContents(self.filter_table)
        self.filter_table.setItemDelegateForColumn(0, EmptyDelegate(self))#第0列不可编辑
        self.filter_table.setItemDelegateForColumn(1, EmptyDelegate(self))  # 第1列不可编辑

        for i, key in enumerate(self.filter.keys()):
            self.filter_table.setItem(i, 0, QTableWidgetItem(key))
            self.filter_table.setItem(i, 1, QTableWidgetItem(self.filter[key]))

        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch(1)
        self.button_layout.addWidget(self.ok_button)
        self.button_layout.addWidget(self.cancel_button)
        self.temp_widget = QWidget()
        self.temp_widget.setLayout(self.button_layout)
        self.ok_button.clicked.connect(self.ok_action)
        self.cancel_button.clicked.connect(self.cancel_action)

        self.layout.addWidget(self.filter_table)
        self.layout.addWidget(self.temp_widget)
        self.setLayout(self.layout)
        self.setGeometry(300, 100, 900, 500)

    def ok_action(self):
        for i, key in enumerate(self.filter.keys()):
            try:
                temp_text = self.filter_table.item(i, 2).text()
            except:
                temp_text = ''
            if temp_text != '':
                self.rule += (" and " + temp_text)
        if self.rule != '':
            self.rule = self.rule[5:]
        self.filter_emit.emit(self.rule) #信号，这个和下面那个return_filter可以选一个，也可以都用

    def cancel_action(self):
        self.filter_emit.emit(None)

    def return_filter(self):
        return self.rule


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Filter()
    win.show()
    sys.exit(app.exec_())
