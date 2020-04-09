from PyQt5.QtCore import *
from PyQt5.QtGui import QPixmap, QColor, QFont
from PyQt5.QtWidgets import *
import sys,time
import MainWindow


if __name__ == '__main__':
    app = QApplication(sys.argv)
    splash = QSplashScreen(QPixmap("icon/Logo.png"))
    font1 = QFont("Myriad Pro", 12)
    font1.setBold(True)
    splash.setFont(font1)
    splash.showMessage("Initializing ...", Qt.AlignVCenter|Qt.AlignHCenter, QColor("#DBF705"))
    splash.show()
    qApp.processEvents()

    GUI_Window = MainWindow.MainWindow()
    GUI_Window.OpenUI(splash)
    splash.finish(GUI_Window)
    GUI_Window.show()

    #GUI_Window.show()
    sys.exit(app.exec_())