#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'
from threading import Thread
from time import sleep

from PyQt5 import QtCore, QtGui, QtWidgets, Qt
from PyQt5.QtCore import pyqtSlot, pyqtSignal, QObject
from PyQt5.QtGui import QBrush, QPalette
from PyQt5.QtGui import QPainter, QColor
from main import BOLVANIZATOR
dict_t = {}
dict_t['main_table'] = {}
for i in range (1, 23):
    dict_t['main_table'][i] = {'port': i,
                               'status_port':  '',
                               'IP_switch': '',
                               'snmp_params': '',
                               'ping': '',
                               'model': '',
                               'serial_number': '',
                               'MAC': '',
                               'status_fw_up': '',
                               'actual_firmware': '',
                               'firmware_up': '',
                               'write_bd': ''
                               }

class Ui_MainWindow(QObject):
    def __init__(self, MainWindow):
        super().__init__()
        self.thread = QtCore.QThread()

        self.setupUi(MainWindow)
        self.ex = BOLVANIZATOR()
        self.ex.moveToThread(self.thread)
        self.ex.mysignal.connect(self.print_table)
        self.ex.button_sig.connect(self.enable_button)
        self.ex.after_sig.connect(self.after)
        self.ex.final.connect(self.finish)

        print(self.ip.text())
        self.ip.textChanged.connect(self.change_ip)
        self.start_port.textChanged.connect(self.change_port)
        self.final_port.textChanged.connect(self.change_port)


    @pyqtSlot()
    def start_button(self):
        print('click')
        self.pushButton.setText("Ожидайте")
        self.pushButton.setEnabled(False)

        self.thread.started.connect(self.ex.run_action)
        self.thread.start()
        self.pushButton.clicked.connect(self.run)

    @pyqtSlot()
    def enable_button(self):
        self.pushButton.setEnabled(True)
        self.pushButton.setText("Оболванить")

    @pyqtSlot()
    def finish(self):
        #  self.pushButton.setEnabled(True)
        self.pushButton.setStyleSheet("background-color: green")
        self.pushButton.setText("Обновление ПО завершено")

    def write_data(self, dict):
        print(dict)

    def setupUi(self, MainWindow):

        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1500, 650)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(30, 80, 1400, 41))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.start_button)
        self.pushButton.setText("Ожидайте")

        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(340, 20, 81, 21))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(680, 20, 81, 21))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(910, 20, 81, 21))
        self.label_4.setObjectName("label_4")


        self.graphicsView_2 = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphicsView_2.setGeometry(QtCore.QRect(290, 10, 41, 41))
        self.graphicsView_2.setObjectName("graphicsView_2")
        self.graphicsView_2.setStyleSheet("background-color: red")

        self.graphicsView_3 = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphicsView_3.setGeometry(QtCore.QRect(630, 10, 41, 41))
        self.graphicsView_3.setObjectName("graphicsView_3")
        self.graphicsView_3.setStyleSheet("background-color: red")

        self.graphicsView_4 = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphicsView_4.setGeometry(QtCore.QRect(860, 10, 41, 41))
        self.graphicsView_4.setObjectName("graphicsView_4")
        self.graphicsView_4.setStyleSheet("background-color: red")


        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(1010, 20, 81, 21))
        self.label_5.setObjectName("label_5")


        self.ip = QtWidgets.QLineEdit(self.centralwidget)
        self.ip.setGeometry(QtCore.QRect(1080, 20, 81, 21))
        self.ip.setObjectName("ip")
        self.ip.insert('192.168.1.99')
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(1190, 20, 81, 21))
        self.label_6.setObjectName("label_6")


        self.start_port = QtWidgets.QLineEdit(self.centralwidget)
        self.start_port.setGeometry(QtCore.QRect(1250, 20, 21, 21))
        self.start_port.setObjectName("start_port")
        self.start_port.insert('1')

        self.final_port = QtWidgets.QLineEdit(self.centralwidget)
        self.final_port.setGeometry(QtCore.QRect(1280, 20, 21, 21))
        self.final_port.setObjectName("start_port")
        self.final_port.insert('20')


        self.tableView = QtWidgets.QTableView(self.centralwidget)
        self.tableView.setGeometry(QtCore.QRect(30, 140, 1400, 600))
        self.tableView.setObjectName("tableView")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.tableModel = QtGui.QStandardItemModel(parent=None)
        self.tableModel.setRowCount(len(dict_t['main_table'].keys()))
        self.tableModel.setColumnCount(len(dict_t['main_table'][1]))
        self.tableModel.setHorizontalHeaderLabels(dict_t['main_table'][1].keys())
        self.tableView.setModel(self.tableModel)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.print_table(dict_t)
        # self.set_tftp_status(True)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "BOLVANIZATOR(created_by_Pykhova_Olga)"))
        self.pushButton.setText(_translate("MainWindow", "Старт"))

        self.label_2.setText(_translate("MainWindow", "Коммутатор"))
        self.label_3.setText(_translate("MainWindow", "tftp сервер"))
        self.label_4.setText(_translate("MainWindow", "База данных"))
        self.label_5.setText(_translate("MainWindow", "Ip стенда"))
        self.label_6.setText(_translate("MainWindow", "Порты"))



    def set_comm_status(self, ok):
        if ok:
            self.graphicsView_2.setStyleSheet("background-color: green")
        else:
            self.graphicsView_2.setStyleSheet("background-color: red")

    def set_tftp_status(self, ok):
        if ok:
            self.graphicsView_3.setStyleSheet("background-color: green")
        else:
            self.graphicsView_3.setStyleSheet("background-color: red")

    def set_bd_status(self, ok):
        if ok:
            self.graphicsView_4.setStyleSheet("background-color: green")
        else:
            self.graphicsView_4.setStyleSheet("background-color: red")

    @pyqtSlot(dict)
    def print_table(self, dic):
        general = dic.get('general')
        if general is not None:

            self.set_comm_status(general.get('SWITCH', False))
            self.set_tftp_status(general.get('TFTP_SERVER', False))
            self.set_bd_status(general.get('BD', False))

        dic = dic.get('main_table')
        self.tableModel.resetInternalData()
        try:
            self.tableModel.setRowCount(len(dic.keys()))
            self.tableModel.setColumnCount(len(dic[1].keys()))
            self.tableModel.setHorizontalHeaderLabels(dic[1].keys())
        except Exception:
            pass
        try:
            for row, i in dic.items():
                column = 0
                # if i.get('ping') == "No data":
                #     continue
                for key in i.keys():
                    item = QtGui.QStandardItem()
                    item.setData(str(i[key]), QtCore.Qt.DisplayRole)
                    self.tableModel.setItem(row -1, column, item)
                    column += 1
        except Exception:
            pass
        self.tableView.setModel(self.tableModel)
        print('table')



    @pyqtSlot()
    def run(self):
        self.pushButton.setEnabled(False)
        self.pushButton.setText("Ожидайте")

        self.thread_after = QtCore.QThread()
        self.ex.moveToThread(self.thread_after)
        self.thread_after.started.connect(self.ex.obolvanit)
        self.thread_after.start()


    @pyqtSlot()
    def after(self):
        self.thread_after_2 = QtCore.QThread()
        self.ex.moveToThread(self.thread_after_2)
        self.thread_after_2.started.connect(self.ex.check_after_fw_up)
        self.thread_after_2.start()

    @pyqtSlot()
    def change_ip(self):
        self.ex.set_ip(self.ip.text)

    @pyqtSlot()
    def change_port(self):
        try:
            self.ex.set_port(int(self.start_port.text()), int(self.final_port.text()))
        except Exception:
            pass


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow(MainWindow)

    MainWindow.show()
    sys.exit(app.exec_())
