from PyQt5.QtCore import Qt,pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtWidgets import *
from scapy.all import *
import sys, time, copy
# Files Import
import CentralWidget
import SnifferThread
import Filter
import ResultTable
import ChooseFileType
import ReassembleWidget
import base64

global symbol
symbol = {'JPG' : b'\xff\xd8\xff\xe0\x00\x10JFIF',
          'JPEG': b'\xff\xd8\xff\xe0\x00\x10JFIF',
          'GIF' : b'GIF',
          'PNG' : b'\x89PNG',
          'M4A' : b'isom',         #########!!!!!!##########
          'WAV' : b'WAVEfmt',
          'MP3' : b'ID3',
          'WMA' : b'0&\xb2u\x8ef',
          'MP4' : b'isom',            #######!!!!!!!!##############
          'AVI' : b'AVI LIST',
          'MOV' : b'\x00\x00\x00\x14ftypqt'
          }

class MainWindow(QMainWindow):

    Signal_StopSniff_Action = pyqtSignal(bool)
    def __init__(self):
        super().__init__()

        self.PktCount = 0
        self.Time_Start = 0
        self.HistoryPacket={}
        self.CurrentRow = 0
        self.CurrentPacket = {}  #########################!!!!!!!!!!!!#############
        self.current_row = None  ############################!!!!!!!!!!!!!##############
        self.FilterRule = ''
        self.initUI()

        # Signals
        self.Signal_SniffStop_Interf = self.CentralWidget.Signal_SniffStop_Interf
        self.Signal_SniffStop_Interf.connect(self.Stop)
        self.Signal_SniffStop_Interf.connect(self.PktTableClear)
        self.Signal_SniffStop_Interf.connect(self.ResultTableClear)
        self.Signal_Filter  = self.Filter.filter_emit
        self.Signal_Filter.connect(self.AddFilter)
        self.Signal_Reass = self.ReassembleWidget.Signal_Reass
        self.Signal_Reass.connect(self.ReassShowDetail)
        self.Signal_ChooseFileType = self.ChooseFileType.Signal_ChooseEmit
        self.Signal_ChooseFileType.connect(self.AddChooseFileType)

    def initUI(self):
        self.setWindowTitle("Sniffer  Version 1.0.1 191218")
        self.setWindowIcon(QIcon("icon/Logo.png"))
        self.setGeometry(200, 100, 1200, 950)


    # QAction Definition
        
        self.action_Start = QAction(QIcon("icon/Start.png"),"&Start Sniffer",self)
        self.action_Start.setStatusTip("Start Sniffer")
        self.action_Start.setShortcut('Ctrl+E')
        self.action_Start.triggered.connect(self.Start)
        
        self.action_Stop = QAction(QIcon("icon/Stop.png"),"&Stop Sniffer",self)
        self.action_Stop.setStatusTip("Stop Sniffer")
        self.action_Stop.setShortcut('Ctrl+F')
        self.action_Stop.triggered.connect(self.Stop)

        self.action_Restart = QAction(QIcon("icon/Restart.png"),"&Restart Sniffer",self)
        self.action_Restart.setStatusTip("Restart Sniffer")
        self.action_Restart.setShortcut('Ctrl+R')
        self.action_Restart.triggered.connect(self.Restart)

        self.action_Clear = QAction(QIcon("icon/Clear.png"), "&Clean All", self)
        self.action_Clear.setStatusTip("Clean all tables and histories")
        self.action_Clear.setShortcut('Ctrl+C')
        self.action_Clear.triggered.connect(self.Clear)

        self.action_ShowDetail = QAction(QIcon("icon/Detail.png"), "&Show Details", self)
        self.action_ShowDetail.setStatusTip("Show Packet Details")
        self.action_ShowDetail.setShortcut('Ctrl+D')
        self.action_ShowDetail.triggered.connect(self.ShowDetail)

        self.action_OpenFile = QAction(QIcon("icon/File.png"),"&Open File",self)
        self.action_OpenFile.setStatusTip("Open a ..cap File")
        self.action_OpenFile.setShortcut('Ctrl+O')
        self.action_OpenFile.triggered.connect(self.OpenFile)
                                       
        self.action_SaveasFile = QAction(QIcon("icon/Save.png"),"&Save as..",self)
        self.action_SaveasFile.setStatusTip("Save Result as a ..cap File")
        self.action_SaveasFile.setShortcut('Ctrl+S')
        self.action_SaveasFile.triggered.connect(self.SaveasFile)

        self.action_UseFilter = QAction(QIcon("icon/Filter.png"),"&Filter",self)
        self.action_UseFilter.setStatusTip("Activate a Filter")
        self.action_UseFilter.setShortcut('Ctrl+F')
        self.action_UseFilter.triggered.connect(self.UseFilter)

        self.action_Back = QAction(QIcon("icon/Back.png"), "&Back", self)  ##########!!!!!!!!!!!!#############
        self.action_Back.setStatusTip("Back")
        self.action_Back.setShortcut('Ctrl+B')
        self.action_Back.triggered.connect(self.ShowHistory)

        self.action_Reassemble = QAction(QIcon("icon/Reassemble.png"),"&Reassemble",self)
        self.action_Reassemble.setStatusTip("Reassemble File from Packets")
        self.action_Reassemble.setShortcut('Ctrl+M')
        self.action_Reassemble.triggered.connect(self.Reassemble)

        self.action_SearchToFile = QAction(QIcon("icon/SearchToFile.png"), "&SearchToFile", self)
        self.action_SearchToFile.setStatusTip("Select packets automatically and then transform them to File")
        self.action_SearchToFile.setShortcut('Ctrl+H')
        self.action_SearchToFile.triggered.connect(self.SearchToFile)

        self.action_ChooseFileType = QAction(QIcon("icon/ChooseFileType.png"), "&ChooseFileType",
                                             self)
        self.action_ChooseFileType.setStatusTip("ChooseFileType")
        self.action_ChooseFileType.setShortcut('Ctrl+P')
        self.action_ChooseFileType.triggered.connect(self.UseChooseFileType)

        self.action_TcpToFile = QAction(QIcon("icon/TcpToFile.png"), "&TcpToFile", self)
        self.action_TcpToFile.setStatusTip("Transform Tcp Packets to File")
        self.action_TcpToFile.setShortcut('Ctrl+T')
        self.action_TcpToFile.triggered.connect(self.TcpToFile)

        self.action_Exit = QAction(QIcon("icon/Exit.png"),"&Exit",self)
        self.action_Exit.setStatusTip("Exit")
        self.action_Exit.setShortcut('Ctrl+Q')
        self.action_Exit.triggered.connect(self.Exit)

    # MenuBar
        self.menubar = self.menuBar()

        # File
        self.menu_File = self.menubar.addMenu("File(&F)")
        self.menu_File.addAction(self.action_OpenFile)
        self.menu_File.addAction(self.action_SaveasFile)
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.action_Exit)

        # Run
        self.menu_Run = self.menubar.addMenu("Sniffer(&S)")
        self.menu_Run.addAction(self.action_Start)
        self.menu_Run.addAction(self.action_Stop)
        self.menu_Run.addAction(self.action_Restart)
        self.menu_Run.addAction(self.action_Clear)

        # Tool
        self.menu_Tool = self.menubar.addMenu("Tool(&T)")
        self.menu_Tool.addAction(self.action_UseFilter)
        self.menu_Tool.addAction(self.action_ShowDetail)
        self.menu_Tool.addAction(self.action_Reassemble)
        self.menu_Tool.addAction(self.action_ChooseFileType)
        self.menu_Tool.addAction(self.action_SearchToFile)
        self.menu_Tool.addAction(self.action_TcpToFile)

    # ToolBar
        self.toolbar1 = QToolBar()
        self.toolbar2 = QToolBar()
        self.addToolBar(Qt.LeftToolBarArea, self.toolbar1)
        self.addToolBar(Qt.LeftToolBarArea, self.toolbar2)
        self.toolbar1.addAction(self.action_Start)
        self.toolbar1.addAction(self.action_Stop)
        self.toolbar1.addAction(self.action_Restart)
        self.toolbar1.addAction(self.action_Clear)
        self.toolbar1.addAction(self.action_OpenFile)
        self.toolbar1.addAction(self.action_SaveasFile)
        self.toolbar2.addAction(self.action_ShowDetail)
        self.toolbar2.addAction(self.action_UseFilter)
        self.toolbar2.addAction(self.action_Reassemble)
        self.toolbar2.addAction(self.action_ChooseFileType)
        self.toolbar2.addAction(self.action_Back)
        self.toolbar2.addAction(self.action_SearchToFile)
        self.toolbar2.addAction(self.action_TcpToFile)
        self.toolbar2.addAction(self.action_Exit)
        self.toolbar1.setStyleSheet(""" QToolBar {border: 2px outset gray;}                                  
                                    """)
        self.toolbar2.setStyleSheet(""" QToolBar {border: 2px outset gray;}                                                                        
                                    """)
    # Widgets Setting

        self.Layout = QGridLayout()

        # DockWidget Settings
        self.setDockNestingEnabled(True)

        self.CentralWidget = CentralWidget.CentralWidget()
        self.Signal_SniffStop_Interf = self.CentralWidget.Signal_SniffStop_Interf
        self.Signal_SniffStop_Interf.connect(self.Stop)
        self.setCentralWidget(self.CentralWidget)
        self.Interf = self.CentralWidget.Interf
        self.CentralWidget.pkt_table_cellClicked.connect(self.ResultUpdate)  #########!!!!!!!!!!!!####################################
        self.CentralWidget.search.clicked.connect(self.SearchPacket)  #################!!!!!!!##############

        self.Filter = Filter.Filter()
        self.Dock_Filter = QDockWidget('Filter',self)
        self.Dock_Filter.setWidget(self.Filter)
        self.Dock_Filter.setFeatures(QDockWidget.AllDockWidgetFeatures)
        self.Dock_Filter.setAllowedAreas(Qt.TopDockWidgetArea | Qt.BottomDockWidgetArea
                                         | Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)


        self.ReassembleWidget = ReassembleWidget.ReassembleWidget()
        self.Dock_ReassembleWidget = QDockWidget('Reassemble Packet',self)
        self.Dock_ReassembleWidget.setWidget(self.ReassembleWidget)
        self.Dock_ReassembleWidget.setFeatures(QDockWidget.AllDockWidgetFeatures)
        self.Dock_ReassembleWidget.setAllowedAreas(Qt.TopDockWidgetArea | Qt.BottomDockWidgetArea
                                         | Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)

        self.ResultTable = ResultTable.ResultTable()
        self.Dock_ResultTable = QDockWidget('Details', self)
        self.Dock_ResultTable.setWidget(self.ResultTable)
        self.Dock_ResultTable.setFeatures(QDockWidget.AllDockWidgetFeatures)
        self.Dock_ResultTable.setAllowedAreas(Qt.TopDockWidgetArea | Qt.BottomDockWidgetArea
                                          | Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)

        self.ChooseFileType = ChooseFileType.ChooseFileType()
        self.Dock_ChooseFileType = QDockWidget('ChooseFileType', self)
        self.Dock_ChooseFileType.setWidget(self.ChooseFileType)
        self.Dock_ChooseFileType.setFeatures(QDockWidget.AllDockWidgetFeatures)
        self.Dock_ChooseFileType.setAllowedAreas(Qt.TopDockWidgetArea | Qt.BottomDockWidgetArea
                                        | Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)

        self.addDockWidget(Qt.RightDockWidgetArea,self.Dock_Filter)
        self.addDockWidget(Qt.RightDockWidgetArea, self.Dock_ReassembleWidget)
        self.addDockWidget(Qt.BottomDockWidgetArea,self.Dock_ResultTable)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.Dock_ChooseFileType)
        self.setLayout(self.Layout)
        self.Dock_Filter.close()
        self.Dock_ReassembleWidget.close()
        self.Dock_ChooseFileType.close()


    # Initial Actions
        self.action_Stop.setEnabled(False)
        self.CheckInterf()
        self.action_Restart.setEnabled(False)
        self.action_Clear.setEnabled(False)
        self.action_SaveasFile.setEnabled(False)

    # Functions
    # Splash!
    def OpenUI(self, splash):
        time.sleep(0.9)
        for i in range(1, 101):
            time.sleep(0.0065)
            splash.showMessage("Loading...    {}%".format(i),
                               Qt.AlignVCenter | Qt.AlignHCenter, QColor("#DBF705"))
            qApp.processEvents()

    # Main Sniffer Functions
    def GetInterf(self):
        self.Interf = self.CentralWidget.Interf

    def Initialize(self):
        self.PktTableClear()
        self.ResultTableClear()
        del self.HistoryPacket
        self.HistoryPacket = {}
        del self.CurrentPacket
        self.CurrentPacket = {}
        self.PktCount = 0
        self.current_row = None

    def Clear(self):
        Reply = QMessageBox.question(self, 'Clear?',
                                     "This operation will reset the sniffer and clear tables.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if Reply == QMessageBox.Yes:
            self.Initialize()
        self.action_Restart.setEnabled(False)
        self.action_SaveasFile.setEnabled(False)
        
    def StartSniffer(self):
        self.Sniffer = SnifferThread.SnifferThread(Signal_SniffStop = self.Signal_StopSniff_Action,
                                                           PktCount = self.PktCount,
                                                           Interf = self.Interf ,Filter = self.FilterRule)
        self.Sniffer.start()
        self.Sniffer.Signal_UpdateShow.connect(self.UpdatePacketTable) # The signal return count and packet
        self.action_Start.setEnabled(False)
        self.action_Stop.setEnabled(True)
        self.action_Restart.setEnabled(False)
        self.action_Clear.setEnabled(False)
        self.action_SaveasFile.setEnabled(False)
        self.action_OpenFile.setEnabled(False)
        self.action_UseFilter.setEnabled(False)
        self.action_Exit.setEnabled(False)
        
    def Start(self):
        self.Signal_StopSniff_Action.emit(True)
        if self.PktCount == 0:
            self.Initialize()
            self.Time_Start = time.time()
        if self.Time_Start == 0:
            self.Time_Start = time.time()
        self.StartSniffer()
        
    def CheckInterf(self):
        self.GetInterf()
        if self.Interf == ' ':
            self.action_Start.setEnabled(False)
            self.action_Restart.setEnabled(False)
        else:
            self.action_Start.setEnabled(True)
            self.action_Restart.setEnabled(True)

    def Restart(self):
        self.Initialize()
        self.Time_Start = time.time()
        self.Start()
        
    def Stop(self):
        self.Signal_StopSniff_Action.emit(True)
        self.CheckInterf()
        self.action_Stop.setEnabled(False)
        self.action_Clear.setEnabled(True)
        self.action_SaveasFile.setEnabled(True)
        self.action_OpenFile.setEnabled(True)
        self.action_UseFilter.setEnabled(True)
        self.action_Exit.setEnabled(True)

    def Exit(self):
        Reply = QMessageBox.question(self, 'EXIT ?',
            "Do you really want to EXIT ?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No )
        if Reply == QMessageBox.Yes:
            self.close()

    # PacketTable
    def UpdatePacketTable(self, No, pkt: Packet):
        RowNum = self.CentralWidget.UpdatePacketTable(No-1, self.Time_Start, pkt)
        self.HistoryPacket[str(RowNum)] = pkt
        self.PktCount = len(self.HistoryPacket)
        self.CurrentPacket = self.HistoryPacket

    def UpdateSearchPacketTable(self, No, pkt:Packet):          ##############!!!!!!!!!!!!################
        self.CentralWidget.UpdatePacketTable(No, self.Time_Start, pkt)     ######error###########

    def PktTableClear(self):
        self.CentralWidget.PktTableClear()

    # Result and Reassemble

    def ResultUpdate(self, row):
        if row != self.current_row:
            self.current_row = row
            pkt = self.CurrentPacket[str(self.current_row)]
            #self.ResultTable.clear()
            self.ResultTable.ShowDetail(pkt)

    def ShowHistory(self):
        self.Stop()
        self.CentralWidget.pkt_table.clear()
        self.ResultTable.clear()
        self.CurrentPacket = self.HistoryPacket
        for temp_key in self.HistoryPacket.keys():
            self.UpdateSearchPacketTable(temp_key, self.HistoryPacket[temp_key])

    def ReassembleUpdate(self, pdict):
        self.ReassembleWidget.UpdateReassemble(self.Time_Start, pdict)

    def ShowDetail(self):
        self.Dock_ResultTable.show()

    def ReassShowDetail(self,pkt):
        self.ResultTable.ShowDetail(pkt)

    def ResultTableClear(self):
        self.ResultTable.clear()
        self.ReassembleWidget.clear()

    # Filter
    def UseFilter(self):
        self.Dock_Filter.show()

    def AddFilter(self,rule):
        self.FilterRule = rule
        self.Dock_Filter.close()

    # Choose Filetype
    def UseChooseFileType(self):
        self.Dock_ChooseFileType.show()

    def AddChooseFileType(self, filetype):
        self.FileList = filetype
        print(self.FileList)
        self.Dock_ChooseFileType.close()
        if len(self.FileList) > 0:
            self.ChoosePktFile()

    def TestIfTXT(self, temp_bytes):
        #value_list = []
        #for i in range(len(symbol)):
        #    value_list.append(symbol.values()[i])
        for i in symbol.keys():
            if symbol[i] in temp_bytes:
                return False
        return True

    def ChoosePktFile(self):
        File_sym = []
        for i in symbol.keys():
            if i in self.FileList:
                File_sym.append(symbol[i])
        TXT_flag = False
        if 'TXT' in self.FileList:
            TXT_flag = True
        print(TXT_flag)
        current_row = 0
        overall_list = []
        type_list = []
        temp_list = []
        flag = True
        while current_row < len(self.HistoryPacket):
            print(current_row)
            try:
                temp_raw = self.HistoryPacket[str(current_row)][Raw].load
                flag = True
            except:
                flag = False
            save_flag = False
            if flag:
                #print(SnifferThread.GetProtocol(self.HistoryPacket[str(current_row)]))
                #if SnifferThread.GetProtocol(self.HistoryPacket[str(current_row)]) == 'TCP' and (len(self.HistoryPacket[str(current_row)]) > 200):
                if b'Content-Length' in temp_raw:
                    print("uuuuuuuuuuuuuuuuuuuuuuuuu")
                    print(current_row)
                    info_pkt = self.HistoryPacket[str(current_row)]
                    length = self.SearchLength(str(info_pkt[Raw].load))
                    start_id = int(info_pkt[IP].id) + 1
                    print(length)
                    print(start_id)
                    current_row += 1
                    current_id = start_id
                    temp = b''
                    temp_dict = {}
                    temp_list = []
                    temp_flag = False
                    temp_list.append(current_row-1)
                    #print("wwwwwwwwwwwwwwwwwwwwwww")
                    next_start_row = current_row
                    save_flag = False
                    while current_row < len(self.HistoryPacket):
                        print(current_row)
                        try:
                            temp_raw = self.HistoryPacket[str(current_row)][Raw].load
                            flag = True
                        except:
                            flag = False
                        if SnifferThread.GetProtocol(self.HistoryPacket[str(current_row)]) == 'TCP' and flag and self.HistoryPacket[str(current_row)][IP].id == start_id:
                            print("true")
                            for i in range(len(File_sym)):
                                if File_sym[i] in self.HistoryPacket[str(current_row)][Raw].load:
                                    temp_flag = True
                                    save_flag = True
                                    print("ttttttttttttrrrrrrrrrrrrruuuuuuuuuuuuuuuuuueeeeeeeeeeeeeeee")
                                    type_list.append(self.FileList[i])
                            print(temp_flag)
                            print(TXT_flag)
                            print(self.TestIfTXT(self.HistoryPacket[str(current_row)][Raw].load))
                            if temp_flag == False:
                                if(TXT_flag):
                                    if(self.TestIfTXT(self.HistoryPacket[str(current_row)][Raw].load)):
                                        print("7777777777777777777777777777777777777777777")
                                        temp_flag = True
                                        save_flag = True
                                        type_list.append('TXT')
                                else:
                                    break
                        if SnifferThread.GetProtocol(self.HistoryPacket[str(current_row)]) == 'TCP' and flag:
                            temp_dict[self.HistoryPacket[str(current_row)][IP].id] = current_row
                        current_row += 1
                    #print(temp_dict)
                    while len(temp) < length and temp_flag:
                        if current_id in temp_dict.keys():
                            temp += self.HistoryPacket[str(temp_dict[current_id])][Raw].load
                            temp_list.append(temp_dict[current_id])
                            #print(temp_dict[current_id])
                            #print(temp_dict[current_id])
                            # print(len(self.CurrentPacket[str(temp_dict[current_id])][Raw].load))
                            current_id += 1
                        else:
                            QMessageBox.question(self, "There is something wrong.",
                                             "You lose some packets. We just try and don't promise anything.",
                                             QMessageBox.Yes)
                            break
                    if(len(temp) > length):
                        temp_list = []
                        type_list = type_list[:-1]
            if save_flag == True:
                current_row = next_start_row
            else:
                current_row += 1
            if len(temp_list) > 1:
                overall_list.append(temp_list)
                temp_list = []
        print(overall_list)
        print(type_list)
        self.Stop()
        self.CentralWidget.pkt_table.clear()
        self.ResultTable.clear()
        self.CurrentPacket = {}
        for i in range(len(overall_list)):
            for j in range(len(overall_list[i])):
                temp_search = str(len(self.CurrentPacket))
                self.CurrentPacket[temp_search] = self.HistoryPacket[str(overall_list[i][j])]
                self.UpdateSearchPacketTable(str(overall_list[i][j]), self.CurrentPacket[temp_search])
        QMessageBox.question(self, "Prompt information.",
                             "Packets are arranged in the following order : %s" % repr(type_list),
                             QMessageBox.Yes)

    # File Operations
    def OpenFile(self):
        FileName, FileType = QFileDialog.getOpenFileName(self,
                                            "Sniffer: Open Capture File", "./",
                                            "WireShark Tcpdump (*.cap *.pcap);;All Files (*);;")
        if FileName:
            try:
                FilePkt = rdpcap(FileName)
                self.Initialize()
                print("  ### Open File : %s ###  "%FileName)
                for index, pkt in enumerate(FilePkt):
                    print(index)
                    print(pkt)
                    self.HistoryPacket[str(index)] = pkt
                    pkt_information = self.CentralWidget.BuildPktDict(index, 0, pkt)   #######!!!!!!!########
                    #self.CentralWidget.InsertRowByIndex(index, pkt_information)
                    self.CentralWidget.InsertPkt(pkt_information)
                    self.PktCount += 1
                    self.CurrentPacket = self.HistoryPacket
                print("  ### File Opened ###  ")
                self.action_SaveasFile.setEnabled(True)
            except:
                QMessageBox.question(self,"Invalid File!",
                                     "Cannot open this file, please have a check!",
                                     QMessageBox.Yes)

    def SaveasFile(self):
        try:
            SelectedIndexes = self.CentralWidget.pkt_table.tablewidget.selectedIndexes()
            RowIndex = set(Index.row() for Index in SelectedIndexes)
            if RowIndex:
                SavePktDict = {}
                for index in RowIndex:
                    ###############!!!!!!!!!!!!!###############
                    SavePktDict[str(index)] = self.CurrentPacket[str(index)]
                    #SavePktDict[str(index)] = self.HistoryPacket[str(index)]
            else:
                #SavePktDict = self.HistoryPacket             #########!!!!!!!!!!!###########
                SavePktDict = self.CurrentPacket
            if SavePktDict == {}:
                QMessageBox.question(self,"No Packet to Save!",
                                    "No Packet will be saved, please have a check.",
                                    QMessageBox.Yes)
            else:
                FileSavePath, FilePointer = QFileDialog.getSaveFileName(self,
                                            "Sniffer: Save File","./",
                                            "WireShark Tcpdump (*.cap *.pcap);;All Files (*)")
                if FileSavePath:
                    print("  ### Save File : %s ###  "%FileSavePath)
                    SaveOperList = PacketList()
                    for key in SavePktDict.keys():
                        SaveOperList.append(SavePktDict[key])
                    wrpcap(FileSavePath, SaveOperList)     #######change here
                    print("  ### File Saved ###  ")
        except:
            QMessageBox.question(self, "No Packet to Save!",
                             "No Packet will be saved, please have a check.",
                             QMessageBox.Yes)

    def TcpToFile(self):
        flag = True
        try:
            SelectedIndexes = self.CentralWidget.pkt_table.tablewidget.selectedIndexes()
            RowIndex = set(Index.row() for Index in SelectedIndexes)
            flag = True
        except:
            flag = False
            QMessageBox.question(self, "There is something wrong.",
                                 "Please choose some indexes.",
                                 QMessageBox.Yes)
        if flag:
            #print(RowIndex)
            if RowIndex:
                SavePktDict = {}
                for index in RowIndex:
                    SavePktDict[index] = self.CurrentPacket[str(index)]
            else:
                SavePktDict = self.CurrentPacket
            print(SavePktDict.keys())
            if SavePktDict == {}:
                QMessageBox.question(self,"No Packet to Save!",
                                    "No Packet will be saved, please have a check.",
                                    QMessageBox.Yes)
            else:
                FileSavePath, FilePointer = QFileDialog.getSaveFileName(self,
                                                                        "Sniffer: Save data to File", "./",
                                                                        "All Files (*);;Text Files (*.txt);;Word Files (*.docx);; Old Word Files(*.doc);;" +
                                                                        "JPG Files (*.JPG);;JPEG Files (*.JPEG);;GIF Files (*.GIF);;PNG Files (*.PNG);;" +
                                                                        "M4A Files (*.M4A);;WAV Files (*.WAV);;MP3 Files (*.MP3);;WMA Files (*.WMA);;" +
                                                                        "MP4 Files (*.MP4);;AVI Files (*.AVI);;MOV Files (*.MOV)")
                if FileSavePath:
                    print("  ### Save data to File : %s ###  "%FileSavePath)
                    if 'txt' in FileSavePath or 'doc' in FileSavePath or 'docx' in FileSavePath:
                        #print("11111111111")
                        fout = open(FileSavePath, 'wb')
                        #SaveOperList = PacketList()
                        temp_flag = True
                        for key in sorted(SavePktDict.keys()):
                            try:
                                fout.write(SavePktDict[key][Raw].load)
                            except:
                                temp_flag = False
                        if temp_flag == False:
                            QMessageBox.question(self, "Wrong!",
                                                 "You select some packets which has no raw. We just try.",
                                                 QMessageBox.Yes)
                    else:
                        #print("2222222222222222")
                        flag = True
                        temp_flag = True
                        temp_list = ['jpg', 'JPG', 'jpeg', 'JPEG', 'gif', 'GIF', 'png', 'PNG',
                                     'm4a', 'M4A', 'wav', 'WAV', 'mp3', 'MP3', 'wma', 'WMA',
                                     'mp4', 'MP4', 'avi', 'AVI', 'mov', 'MOV']
                        for i in range(len(temp_list)):
                            if flag:
                                #print(temp_list[i])
                                #print(flag)
                                if temp_list[i] in FileSavePath:
                                    #print("aaaaaaa")
                                    temp = b''
                                    print(sorted(SavePktDict.keys()))
                                    for key in sorted(SavePktDict.keys()):
                                        try:
                                            temp += SavePktDict[key][Raw].load
                                        except:
                                            temp_flag = False
                                    #fout = open("C:/Users/Xin/Desktop/22.txt", 'wb')
                                    #fout.write(temp)
                                    #fout.close()
                                    base64_data = base64.b64encode(temp)
                                    #print("bbbbbbbbbbb")
                                    imgdata = base64.b64decode(base64_data)
                                    #print("ccccccccc")
                                    file = open(FileSavePath, 'wb')
                                    file.write(imgdata)
                                    file.close()
                                    #picture = base64.b64decode(temp)
                                    #with open(FileSavePath, 'wb') as fp:
                                    #    fp.write(picture)
                                    #print("ddddddddddd")
                                    flag = False

                            i += 1
                        if temp_flag == False:
                            QMessageBox.question(self, "Wrong!",
                                                 "You select some packets which has no raw. We just try.",
                                                 QMessageBox.Yes)
                        #print(i)
                        if(i == len(temp_list) and flag == True):
                            QMessageBox.question(self, "Choose the right File Type.",
                                                 "Please choose the right file type.",
                                                 QMessageBox.Yes)
                    print("  ### File Saved ###  ")

    # Search
    def SearchLength(self, information):
        flag = True
        length = 0
        i = 1
        n = 0
        while(flag and i <= len(information)):
            if information[-i] in '0123456789':
                length = length + (10 ** n) * int(information[-i])
                n += 1
            else:
                if length != 0:
                    flag = False
            i += 1
        return length

    def SearchToFile(self):
        try:
            SelectedIndexes = self.CentralWidget.pkt_table.tablewidget.selectedIndexes()
            RowIndex = set(Index.row() for Index in SelectedIndexes)
            if len(RowIndex) != 1:
                QMessageBox.question(self, "There is something wrong.",
                                    "You can only select one packet which contains information about the packets that you need to transfrom..",
                                    QMessageBox.Yes)
                return RowIndex
            else:
                for index in RowIndex:
                    row = index
                print(row)
                info_pkt = self.CurrentPacket[str(row)]
                length = self.SearchLength(str(info_pkt[Raw].load))
                start_id = int(info_pkt[IP].id) + 1
                print(length)
                print(start_id)
                print(len(self.HistoryPacket))
                print(self.HistoryPacket.keys())
                print(len(self.CurrentPacket))
                print(self.CurrentPacket.keys())
                current_row = row + 1
                current_id = start_id
                flag = True
                temp = b''
                temp_dict = {}
                print("sssssssssssssssssss")
                while current_row < len(self.CurrentPacket):
                    print(current_row)
                    if SnifferThread.GetProtocol(self.CurrentPacket[str(current_row)]) == 'TCP':
                        temp_dict[self.CurrentPacket[str(current_row)][IP].id] = current_row
                    current_row += 1
                print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                #print(temp_dict)
                #print(current_id)
                while len(temp) < length:
                    if current_id in temp_dict.keys():
                        temp += self.CurrentPacket[str(temp_dict[current_id])][Raw].load
                        print(temp_dict[current_id])
                        #print(len(self.CurrentPacket[str(temp_dict[current_id])][Raw].load))
                        current_id += 1
                    else:
                        flag = False
                        QMessageBox.question(self, "There is something wrong.",
                                             "You lose some packets. We just try and don't promise anything.",
                                             QMessageBox.Yes)
                        break
                print("bbbbbbbbbbbbbbbbbbbb")
                FileSavePath, FilePointer = QFileDialog.getSaveFileName(self,
                                                                        "Sniffer: Save data to File", "./",
                                                                        "All Files (*);;Text Files (*.txt);;Word Files (*.docx);; Old Word Files(*.doc);;"+
                                                                        "JPG Files (*.JPG);;JPEG Files (*.JPEG);;GIF Files (*.GIF);;PNG Files (*.PNG);;"+
                                                                        "M4A Files (*.M4A);;WAV Files (*.WAV);;MP3 Files (*.MP3);;WMA Files (*.WMA);;"+
                                                                        "MP4 Files (*.MP4);;AVI Files (*.AVI);;MOV Files (*.MOV)")
                if FileSavePath:
                    print("  ### Save data to File : %s ###  " % FileSavePath)
                    if 'txt' in FileSavePath or 'doc' in FileSavePath or 'docx' in FileSavePath:
                        fout = open(FileSavePath, 'wb')
                        fout.write(temp)
                    else:
                        flag1 = True
                        temp_list = ['jpg', 'JPG', 'jpeg', 'JPEG', 'gif', 'GIF', 'png', 'PNG',
                                     'm4a', 'M4A', 'wav', 'WAV', 'mp3', 'MP3', 'wma', 'WMA',
                                     'mp4', 'MP4', 'avi', 'AVI', 'mov', 'MOV']
                        print("cccccccccccccccccccccccc")
                        for i in range(len(temp_list)):
                            if flag1:
                                if temp_list[i] in FileSavePath:
                                    base64_data = base64.b64encode(temp)
                                    imgdata = base64.b64decode(base64_data)
                                    file = open(FileSavePath, 'wb')
                                    file.write(imgdata)
                                    file.close()
                                    flag1 = False
                            i += 1
                        if (i == len(temp_list) and flag1 == True):
                            QMessageBox.question(self, "There is something wrong.",
                                                 "We cannot recognize documents in this format..",
                                                 QMessageBox.Yes)
                    print("  ### File Saved ###  ")
        except:
            QMessageBox.question(self, "There is something wrong.",
                                 "There is something wrong.",
                                 QMessageBox.Yes)


    def SearchPacket(self):
        text = self.CentralWidget.text.text()
        self.CurrentPacket = {}
        if text != '':
            self.Stop()
            self.CentralWidget.pkt_table.clear()
            self.ResultTable.clear()
            for temp_key in self.HistoryPacket.keys():
                if text in repr(self.HistoryPacket[temp_key]):
                    temp_search = str(len(self.CurrentPacket))
                    self.CurrentPacket[temp_search] = self.HistoryPacket[temp_key]
                    self.UpdateSearchPacketTable(temp_key, self.CurrentPacket[temp_search])

    # Packet Reassemble Main Function
    def Reassemble(self):
        self.Dock_ReassembleWidget.show()
        QMessageBox.question(self, "Instruction",
                             "Choose some packets and then click packets in Reassemble Widget.Then you get reassemble details in Detail Widget.",
                             QMessageBox.Yes)

        rows_reassemble = self.CentralWidget.pkt_table.tablewidget.selectedIndexes()
        row_set = set(temp_row.row() for temp_row in rows_reassemble)
        if row_set:
            ReassembleList = PacketList()
            for temp_row in row_set:
                ReassembleList.append(copy.deepcopy(self.CurrentPacket[str(temp_row)]))
            try:
                ReassembleDict = SnifferThread.Reassemble_packet(ReassembleList)
                if ReassembleDict:
                    self.ReassembleWidget.UpdateReassemble(self.Time_Start, ReassembleDict)
                else:
                    QMessageBox.question(self, "Warning", "Please confirm your operation is correct.",
                                         QMessageBox.Yes )
            except:
                QMessageBox.question(self, "Warning", "These packets cannot be reassembled..",
                                     QMessageBox.Yes )
        else:
            QMessageBox.question(self, "Warning", "Oh, man. What do you want to reassemble with nothing selected?.", QMessageBox.Yes)


# Test Module
if __name__ == '__main__':
    app = QApplication(sys.argv)
    GUI_Window = MainWindow()
    GUI_Window.show()
    sys.exit(app.exec_())
