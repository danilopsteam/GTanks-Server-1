# -*- coding: utf8 -*-
import sys
from twisted.python import log
from twisted.internet import reactor, protocol

class GameProtocol(protocol.Protocol):
	def connectionMade(self):
		self.server = self.factory
		self.server.clients.append(self)
		if sys.platform.startswith('win'):
			self.address = self.transport.getPeer().host
		else:
			self.address = self.transport.getHandle().getpeername()[0]
		log.msg('New connection from', self.address)
	
	def connectionLost(self, reason):
		self.server.clients.remove(self)
		print 'Connection lost with', self.address, 'Reason:', reason

	def dataReceived(self, data):
		if data == '<policy-file-request/>\x00':
			#self.policy = True #to stop server only after send policy file
			self.transport.write('<cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\"/></cross-domain-policy>')
			self.transport.loseConnection()
		else:
			data = data.encode('latin-1')
			log.msg('[r]', repr(data)) #This will show packet received
			self.decodePacket(data)
	
	def decodePacket(self, data):
		data = data.split('end~')
		for packet in data:
			if packet != '':
				key = int(packet[:1])
				packet = packet[1:]
				p = ''
				for char in packet:
					p += chr(ord(char)-key)
				self.parsePacket(p)
	
	def parsePacket(self, packet):
		print '[+]', packet

class GameClient(GameProtocol):
	def __init__(self):
		self.address = ''
		print 'New client created'


class GameServer(protocol.ServerFactory):
	def __init__(self):
		self.protocol = GameClient
		self.clients = []
if __name__ == '__main__':
	f = GameServer()
	reactor.listenTCP(443, f)
	log.startLogging(sys.stdout)
	log.msg('Server online on port', 443)
	reactor.run()
