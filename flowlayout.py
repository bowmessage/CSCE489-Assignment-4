#!/usr/bin/env python

"""PyQt4 port of the layouts/flowlayout example from Qt v4.x"""

import sys
from PySide import QtCore, QtGui
from A5 import decode_main


class Window(QtGui.QWidget):

    def __init__(self):
        super(Window, self).__init__()
        self.formLayout = QtGui.QFormLayout()
        openFileButton = QtGui.QPushButton("Open File")
        openFileButton.clicked.connect(self.showDialog)
        self.formLayout.addWidget(openFileButton)
        self.setLayout(self.formLayout)
        self.setWindowTitle("Assignment 4")

        self.fileNameLabel = QtGui.QLabel("File Name")
        self.fileNameLabel.setAlignment(QtCore.Qt.AlignHCenter)
        self.formLayout.addWidget(self.fileNameLabel)

        self.decodeOutputArea = QtGui.QPlainTextEdit("Decoder output")
        self.formLayout.addWidget(self.decodeOutputArea)

        self.assemblyTxtArea = QtGui.QPlainTextEdit("assembly")
        self.formLayout.addWidget(self.assemblyTxtArea)

        self.assemblyPeTxtArea = QtGui.QPlainTextEdit("assembly_pefile")
        self.formLayout.addWidget(self.assemblyPeTxtArea)

    def showDialog(self):
        fileName = QtGui.QFileDialog.getOpenFileName(self,"Open Image", "", "Executable Files (*.exe)")

        self.fileNameLabel.setText(fileName[0])
        self.decodeOutputArea.setPlainText(decode_main(fileName[0]))
        

        with open ("Assembly.txt", "r") as f:
            assemblyTxt=f.read()
            self.assemblyTxtArea.setPlainText(assemblyTxt)
            

        with open ("Assembly_pefile.txt", "r") as f:
            assemblyPeTxt=f.read()
            self.assemblyPeTxtArea.setPlainText(assemblyPeTxt)
            

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    mainWin = Window()
    mainWin.show()
    sys.exit(app.exec_())