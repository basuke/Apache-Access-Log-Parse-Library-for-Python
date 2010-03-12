# -*- encoding: utf-8 -*-

import datetime
import time
import re
import subprocess

def parse(*paths):
	"""
	parse all access logs and return list of logs.
	each item in the list is Log object.
	
	You can specify local or remote files.
	"""
	logs = SuperList()
	
	for path in paths:
		fp = openLogFile(path)
		for line in fp.xreadlines():
			log = parseLogLine(line)
			if log: logs.append(log)
	
	return logs

def openLogFile(path):
	"""
	open local and remote file and return file-like object.
	remote file can be specified as scp does.
	
	if you specify gz compressed file, it was passed to zcat.
	
	sample:
	/home/kanshin/logs/access_log
	aji.kanshin.com:/var/log/httpd/logs/access_log
	"""
	
	args = ()
	
	if path.find(':') >= 0:
		host, path = path.split(':')
		if path.endswith('.gz'):
			exe = 'zcat'
		else:
			exe = 'cat'
		
		args = ('ssh', host, exe, path)
	elif path.endswith('.gz'):
		args = ('zcat', path)
	
	if args:
		p = subprocess.Popen(shell=False, args=args, stdout=subprocess.PIPE)
		return p.stdout
	else:
		return open(path, 'r')

def parseLogLine(line):
	"""
	parse one line of access log and return Log object.
	"""
	match = PATTERN.match(line)
	if not match: return None
	
	return Log(*match.groups())

class SuperList(list):
	def len(self):
		return len(self)
	
	def filter(self, cmp = lambda item: item):
		return SuperList(item for item in self if cmp(item))
	
	def group(self, attr, fget = lambda val: val):
		result = dict()
		for item in self:
			val = fget(getattr(item, attr))
			
			if val not in result:
				result[val] = SuperList()
			
			result[val].append(item)
		
		return result

class Log(object):
	"""
	Object for representing a access log.
	"""
	
	ipaddr = ""
	user = ""
	timestampStr = ""
	_timestampTZ = None
	_timestampTuple = None
	method = ""
	resource = ""
	protocol = ""
	statusCode = ""
	bytes = 0L
	referer = ""
	userAgent = ""
	
	def __init__(self, *cols):
		if len(cols) > 8:
			self.ipaddr = cols[0]
			self.user = cols[2]
			self.timestampStr = cols[3]
			self.method = cols[4]
			self.resource = cols[5]
			self.protocol = cols[6]
			self.statusCode = long(cols[7])
			try:
				self.bytes = long(cols[8])
			except ValueError:
				self.bytes = 0L
		
		if len(cols) > 10:
			self.referer = cols[9]
			self.userAgent = cols[10]
	
	def timestampTuple():
		def fget(self):
			if not self._timestampTuple:
				self._timestampTuple = time.strptime(self.timestampStr[:-6], "%d/%b/%Y:%H:%M:%S")
			
			return self._timestampTuple
		return locals()
			
	timestampTuple = property(**timestampTuple())
	
	def timestampTZ():
		def fget(self):
			if not self._timestampTZ:
				self._timestampTZ = self.timestampStr[-5:]
			
			return self._timestampTZ
		return locals()
			
	timestampTZ = property(**timestampTZ())
	
	year	= property(fget=lambda s: s.timestampTuple[0])
	month	= property(fget=lambda s: s.timestampTuple[1])
	day		= property(fget=lambda s: s.timestampTuple[2])
	hour	= property(fget=lambda s: s.timestampTuple[3])
	minute	= property(fget=lambda s: s.timestampTuple[4])
	second	= property(fget=lambda s: s.timestampTuple[5])
	epoch	= property(fget=lambda s: time.mktime(s.timestampTuple))
	timestamp = property(fget=lambda s: datetime.datetime(*s.timestampTuple[0:6]))
	
	def toTuple(self):
		return (
			self.ipaddr, 
			'-', 
			self.user, 
			self.timestampStr, 
			self.method, 
			self.resource, 
			self.protocol, 
			str(self.statusCode), 
			str(self.bytes) if self.bytes > 0 else '-', 
			self.referer, 
			self.userAgent, 
		)		
	
	def __str__(self):
		return '%s %s %s [%s] "%s %s %s" %s %s "%s" "%s"' % self.toTuple()
	
	def __repr__(self):
		return 'Log' + repr(self.toTuple())

PATTERN = re.compile(
	r"""
		^
		([0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3})
		\s
		([^ ]{1,})
		\s
		([^ ]{1,}|\-)
		\s
		\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{1,4}:[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}
		\s
		[+\-][0-9]{4})\]
		\s
		"([A-Z ]+)
		\s
		([^"]*)
		\s
		([^"]*)"
		\s
		([0-9]{3})
		\s
		([0-9]{1,}|\-)
		(?:
			\s
			"([^"]*|\-)"
			\s
			"([^"]+)"
		)
		$
	""", re.VERBOSE)
	
