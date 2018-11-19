# Author: 	Emmanuel Law
# Version:	1.0
# License: 	MIT License

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IInterceptedProxyMessage
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender,IProxyListener, IContextMenuFactory,ActionListener):
	def registerExtenderCallbacks( self, callbacks):
		# Keep a reference to our callbacks and helper object
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()

		self.stdout = PrintWriter(callbacks.getStdout(), True)

		# Keep Track of Browsers
		self.browsers = {}
		# Colors for different browsers
		self.colors = ["red", "blue", "pink", "green", "magenta", "cyan", "orange", "gray", "yellow"]

		self.callbacks.setExtensionName("Multi-Browser Highlighting")
		self.enabled = False

		self.stdout.println("Multi-Browser Highlighting is loaded")
		if self.enabled:
			self.stdout.println("Highlighting is running, use the context menu to disable")
		else:
			self.stdout.println("Highlighting is stopped, use the context menu to enable")
		self.stdout.println("Available colors: " + ", ".join(self.colors))

		#IExtensionHelpers helpers = callbacks.getHelpers()
		callbacks.registerProxyListener(self)
		callbacks.registerContextMenuFactory(self)
		return

	def processProxyMessage(self, messageIsRequest, message):
		if not self.enabled:
			return
		if not messageIsRequest:
			return
		
		browser_agent = None
		headers = self.helpers.analyzeRequest(message.getMessageInfo()).getHeaders()

		for x in headers:
			# If a color header is defined just set the color
			if x.lower().startswith("color:"):
				color = x.lower()[6:].strip()
				if color in self.colors:
					message.getMessageInfo().setHighlight(color)
					return
			# Check for autochrome UA
			elif x.lower().startswith("user-agent:") and 'autochrome' in x.lower():
				m = re.search(r'autochrome/([a-z]+)', x.lower())
				if m and m.group(1):
					color = m.group(1)
				if color in self.colors:
					message.getMessageInfo().setHighlight(color)
					return
			# Otherwise, use the user-agent
			elif x.lower().startswith("user-agent:"):
				browser_agent = x

		if browser_agent not in self.browsers:
			self.browsers[browser_agent] = {
				"id": len(self.browsers) + 1,
				"agent": browser_agent,
				"color": self.colors.pop()
			}

		self.stdout.println(self.browsers[browser_agent]["agent"])
		message.getMessageInfo().setHighlight(self.browsers[browser_agent]["color"])

	def createMenuItems(self, invocation):
		if invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY:
			mymenu = []
			if self.enabled:
				item = JMenuItem("Multi-Browser Highlight (Running): Click to Disable ")
			else:
				item = JMenuItem("Multi-Browser Highlight (Stopped): Click to Enable ")
			item.addActionListener(self)
			mymenu.append(item)
			return mymenu
		else:
			return None
	
	def actionPerformed(self, actionEvent):
		self.enabled = not self.enabled