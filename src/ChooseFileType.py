import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from scapy.all import *

global FileType
FileType = ['JPG', 'JPEG', 'GIF', 'PNG', 'M4A', 'WAV', 'MP3', 'WMA', 'MP4', 'AVI', 'MOV', 'TXT']

class ChooseFileType(QWidget):
    Signal_ChooseEmit = pyqtSignal(list)
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.layout = QVBoxLayout()
        self.checkBoxs = {}
        self.returnlist = []

        for i, filetype in enumerate(FileType):
            self.checkBoxs[filetype] = QCheckBox(filetype)
            self.checkBoxs[filetype].setObjectName(filetype)
            self.layout.addWidget(self.checkBoxs[filetype])
            self.layout.addStretch(1)

        self.ok_button = QPushButton('OK')
        self.cancel_button = QPushButton('Cancel')
        self.ok_button.clicked.connect(self.ok_action)
        self.cancel_button.clicked.connect(self.cancel_action)

        self.temp_widget = QWidget()
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch(1)
        self.button_layout.addWidget(self.ok_button)
        self.button_layout.addWidget(self.cancel_button)
        self.temp_widget.setLayout(self.button_layout)

        self.layout.addWidget(self.temp_widget)
        self.setLayout(self.layout)
        self.setGeometry(300, 100, 900, 500)

    def ok_action(self):
        self.returnlist = []
        for i, filetype in enumerate(FileType):
            if self.checkBoxs[filetype].isChecked():
                self.returnlist.append(filetype)
        #print(self.returnlist)
        self.Signal_ChooseEmit.emit(self.returnlist)

    def cancel_action(self):
        self.Signal_ChooseEmit.emit([])



if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ChooseFileType()
    win.show()
    sys.exit(app.exec_())
