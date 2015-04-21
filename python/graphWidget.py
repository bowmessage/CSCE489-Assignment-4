#!/usr/bin/env python

from PySide import QtCore, QtGui

class GraphWidget(QtGui.QGraphicsView):

    def __init__(self):
      super(GraphWidget, self).__init__()
      self.cfgScene = QtGui.QGraphicsScene()
      self.setScene(self.cfgScene)

    def showImage(self, filename):
      pixmap = QtGui.QPixmap(filename)
      self.cfgScene.addPixmap(pixmap)
