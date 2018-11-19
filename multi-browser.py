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
		
		set_color = None
		headers = self.helpers.analyzeRequest(message.getMessageInfo()).getHeaders()

		for h in headers:
			h = h.lower()
			# If a color header is defined just set the color
			if h.startswith("color:"):
				color = h[6:].strip()
				if color in self.colors:
					set_color = color
					break
			# Check for autochrome UA
			elif h.startswith("user-agent:") and 'autochrome' in h:
				m = re.search(r'autochrome/([a-z]+)', h)
				if m and m.group(1):
					color = m.group(1)
					if color in self.colors:
						set_color = color
			# Otherwise, use the user-agent
			elif h.startswith("user-agent:"):
				browser_agent = h[11:].strip()
				if browser_agent not in self.browsers:
					self.browsers[browser_agent] = {
						"id": len(self.browsers) + 1,
						"agent": browser_agent,
						"color": self.colors[len(self.browsers) % len(self.colors)]
					}
					self.stdout.println("Found new browser:")
					self.stdout.println("  ID: " + str(self.browsers[browser_agent]["id"]))
					self.stdout.println("  Agent: " + self.browsers[browser_agent]["agent"])
					self.stdout.println("  Color: " + self.browsers[browser_agent]["color"])
				set_color = self.browsers[browser_agent]["color"]

		if not set_color is None:
			message.getMessageInfo().setHighlight(set_color)

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