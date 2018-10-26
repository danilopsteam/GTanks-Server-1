# -*- coding: utf8 -*-
import sys, json
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
			data = u''.join(data.decode('utf8'))
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
		packet = packet.split(';', 1)
		prefix = packet[0]
		packet = packet[1]
		if prefix == 'system':
			if ';' in packet:
				command, packet = packet.split(';', 1)
				if command == 'init_location':
					self.language = packet
			else:
				pass
		elif prefix == 'auth':
			if ';' in packet:
				self.username, packet = packet.split(';', 1)
				self.password, self.remember = packet.rsplit(';', 1)
				print self.username, self.password, self.remember
				self.login()


class GameClient(GameProtocol):
	def __init__(self):
		self.address = ''
		self.language = ''

		self.username = ''
		self.password = ''
		self.remember = ''
		print 'New client created'

	def login(self):
		if self.username != self.password:
			self.sendData('auth', 'accept')
		data = {}
		data['score'] = 0
		data['name'] = self.username
		data['tester'] = False
		data['rating'] = 1
		data['crystall'] = 100000
		data['next_score'] = 100
		data['place'] = 0
		data['rang'] = 1
		data['email'] = None
		self.sendData('lobby', 'init_panel', data)

	def sendData(self, *data):
		send = ''
		for param in data:
			if type(param) == str:
				send = send + param
			elif type(param) == dict:
				send = send + json.dumps(param)
			else:
				send = send + str(param)
			send = send + ';'
		self.transport.write(send + 'end~')

class GameServer(protocol.ServerFactory):
	def __init__(self):
		self.protocol = GameClient
		self.clients = []
if __name__ == '__main__':
	f = GameServer()
	reactor.listenTCP(15050, f)
	log.startLogging(sys.stdout)
	log.msg('Server online on port', 15050)
	reactor.run()
