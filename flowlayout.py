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

    def showDialog(self):
        fileName = QtGui.QFileDialog.getOpenFileName(self,"Open Image", "", "Executable Files (*.exe)")

        self.decodeOutputArea = QtGui.QPlainTextEdit(decode_main(fileName[0]))
        self.formLayout.addWidget(self.decodeOutputArea)

        with open ("Assembly.txt", "r") as f:
            assemblyTxt=f.read()
            self.assemblyTxtArea = QtGui.QPlainTextEdit(assemblyTxt)
            self.formLayout.addWidget(self.assemblyTxtArea)
        with open ("Assembly_pefile.txt", "r") as f:
            assemblyPeTxt=f.read()
            self.assemblyPeTxtArea = QtGui.QPlainTextEdit(assemblyPeTxt)
            self.formLayout.addWidget(self.assemblyPeTxtArea)


        self.textArea.adjustSize()

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    mainWin = Window()
    mainWin.show()
    sys.exit(app.exec_())