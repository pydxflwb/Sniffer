from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon,QPalette,QFont, QColor
from PyQt5.QtWidgets import *
from scapy.all import * 


class InterfaceBox(QWidget):
    Signal_InterfSet = pyqtSignal(bool)     # Whether Interface is chose

    def __init__(self):
        super().__init__()
        self.InterfList0 = get_windows_if_list()
        self.InterfList = []
        for interf in self.InterfList0:
            if interf["mac"]:                       # To delete those who don't have mac addr, such as isatap
                self.InterfList.append(interf)
        self.InterfName = [interf["name"] for interf in self.InterfList]
        # Another method for Linux, note last 2 lines
        # self.InterName = get_if_list()
        self.InterfChose = None
        self.Flag_Interf = True     # To deal with Signal
        self.initUI()

    def initUI(self):
        self.Layout = QHBoxLayout()
        self.Label_Interf = QLabel("Interface ")
        self.Label_Interf.setFont(QFont("Myriad Pro", 12))
        self.Combo_Interf = QComboBox(self)
        self.Combo_Interf.setFont(QFont("Calibri",10))
        self.Combo_Interf.addItem(' ')
        self.Combo_Interf.addItems(self.InterfName)
        self.Combo_Interf.currentTextChanged.connect(self.ChooseInterf)
        self.Layout.addWidget(self.Label_Interf)
        self.Layout.addWidget(self.Combo_Interf)
        self.setLayout(self.Layout)

    #Functions
    def ChooseInterf(self, text):        
        if self.Flag_Interf:
            self.InterfChose = text
            self.Signal_InterfSet.emit(True)

    def BacktoOldInterf(self, text):
        self.Combo_Interf.setCurrentText(text)
        self.InterfChose = text
        self.Flag_Interf = True

if __name__ == '__main__':
    app = QApplication(sys.argv)
    GUI_Window = InterfaceBox()
    GUI_Window.show()
    sys.exit(app.exec_())
