#!/usr/bin/env python

"""PyQt4 port of the layouts/flowlayout example from Qt v4.x"""

import sys, re
from PySide import QtCore, QtGui
from A5 import decode_main, save_histogram_image 
from controlFlowGraph import CFGWidget
from graphWidget import GraphWidget


class Window(QtGui.QWidget):



    def __init__(self):
        super(Window, self).__init__()

        self.fileOpened = False

        self.formLayout = QtGui.QFormLayout()

        openFileButton = QtGui.QPushButton("Open File")
        openFileButton.clicked.connect(self.showDialog)
        self.formLayout.addWidget(openFileButton)
        self.setLayout(self.formLayout)
        self.setWindowTitle("Assignment 5")

        self.tabWidget = QtGui.QTabWidget()


        self.fileNameLabel = QtGui.QLabel("File Name")
        self.fileNameLabel.setAlignment(QtCore.Qt.AlignHCenter)
        #self.formLayout.addWidget(self.fileNameLabel)



        self.decodeOutputArea = QtGui.QPlainTextEdit("Decoder output")
        self.tabWidget.addTab(self.decodeOutputArea, "Decoder Output")

        self.assemblyTxtArea = QtGui.QPlainTextEdit("assembly")
        self.tabWidget.addTab(self.assemblyTxtArea, "Assembly Code Section Output")

        self.assemblyPeTxtArea = QtGui.QPlainTextEdit("imported")
        self.tabWidget.addTab(self.assemblyPeTxtArea, "Imported DLL and Functions")

        self.controlFlowGraph = CFGWidget()
        self.tabWidget.addTab(self.controlFlowGraph, "Control Flow")

        self.graphWidget = GraphWidget()
        self.tabWidget.addTab(self.graphWidget, "Statistics")

        self.tabWidget.setMinimumSize(1800,1000)
        self.showStatistics()


    def showDialog(self):
        fileName = QtGui.QFileDialog.getOpenFileName(self,"Open Image", "", "Executable Files (*.exe)")

        self.fileNameLabel.setText(fileName[0])
        self.decodeOutputArea.setPlainText(decode_main(fileName[0]))
        

        with open ("Assembly.txt", "r") as f:
            assemblyTxt=f.read()
            self.assemblyTxtArea.setPlainText(assemblyTxt)
            

        with open ("Imported.txt", "r") as f:
            assemblyPeTxt=f.read()
            self.assemblyPeTxtArea.setPlainText(assemblyPeTxt)

        with open ("CFG.txt", "r") as f:
          cfgtext=f.read()

        self.controlFlowGraph.setAssemblyText(cfgtext)

        if not self.fileOpened:
            self.formLayout.addWidget(self.fileNameLabel)
            self.formLayout.addWidget(self.tabWidget)
            self.fileOpened = True

    def showStatistics(self):
      opcode_histogram = dict()
      with open ("Assembly.txt", "r") as f:
        for line in f:
          m = re.search("^([\w]+): ([\w]+)", line)
          if m is not None:
			      opcode = m.group(2)
          if opcode in opcode_histogram:
            opcode_histogram[opcode] += 1
          else:
            opcode_histogram[opcode] = 1
      #save_historgram_image(opcode_histogram)

      grouping = {
          'Arithmetic': ['add', 'sub', 'mul', 'imul', 'div', 'idiv', 'neg', 'adc', 'sbb', 'inc', 'dec', 'aaa', 'das'],
          'Logic': ['xor', 'and', 'or', 'not'],
          'Control Flow': ['jz', 'jnz', 'cmp', 'jc', 'ret', 'test', 'jmp', 'je', 'jne', 'jg', 'jge', 'ja', 
                          'jae', 'jl', 'jle', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'call', 'loop', 'enter', 
                          'leave', 'hlt', 'nop', 'lock', 'wait', 'jnl', 'jna', 'jnc', 'jng', 'rep', 'repne' ],
          'Data Transfer': ['mov', 'xchg', 'cmpxchg', 'movz', 'movzx', 'movs', 'movsx', 'movsb', 'lea', 'bswap',
                            'movsd', 'movne', 'cmove', 'cbw', 'cmovne'],
          'Shift and Rotate': ['shr', 'shl', 'sar', 'sal', 'shld', 'shrd', 'ror', 'rol', 'rcr', 'rcl'],
          'Stack Manipulation': ['push', 'pop', 'pushf', 'popf', 'pusha', 'popa', 'pushad', 'popad'],
          'Flags': ['sti', 'cli', 'std', 'cld', 'stc', 'clc', 'cmc', 'sahf', 'lahf', 'setz', 'setnz']
      }

      grouped_histogram = dict()
      grouped_histogram['Other'] = 0
      for opcode in opcode_histogram:
        found = False
        for group in grouping:
          if opcode in grouping[group]:
            if group in grouped_histogram:
              grouped_histogram[group] += opcode_histogram[opcode]
            else:
              grouped_histogram[group] = opcode_histogram[opcode]
            found = True
            break
        if not found:
          grouped_histogram['Other'] += opcode_histogram[opcode]
          
      save_histogram_image(grouped_histogram, 'grouped.png')
      self.graphWidget.showImage('grouped.png')
          

if __name__ == '__main__':

    app = QtGui.QApplication(sys.argv)
    mainWin = Window()
    mainWin.show()
    sys.exit(app.exec_())
