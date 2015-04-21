#!/usr/bin/env python

from PySide import QtCore, QtGui

class CFGWidget(QtGui.QGraphicsView):

    def __init__(self):
      super(CFGWidget, self).__init__()

      self.assemblyText = ""


      self.setDragMode(QtGui.QGraphicsView.ScrollHandDrag)   


      self.cfgScene = QtGui.QGraphicsScene()
      self.setScene(self.cfgScene)


      

    def setAssemblyText(self, text):
      self.assemblyText = text
      textItem = self.cfgScene.addText(text)

    def dragMoveEvent(self, event):
      pass
