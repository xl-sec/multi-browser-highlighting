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
		self.stderr = PrintWriter(callbacks.getStdout(), True)

		# Keep Track of Browsers
		self.browsers = {}
		# Colors for different browsers
		self.colors = ["red", "blue", "pink", "green", "magenta", "cyan", "orange", "gray", "yellow"]
		self.aliases = {"purple": "magenta", "grey": "gray"}

		self.callbacks.setExtensionName("Multi-Browser Highlighting")
		self.enabled = False
		self.automagically = True

		self.stdout.println("Multi-Browser Highlighting is loaded")
		if self.enabled:
			self.stdout.println("Highlighting is running, use the context menu to disable")
		else:
			self.stdout.println("Highlighting is stopped, use the context menu to enable")
		self.stdout.println("Available colors: " + ", ".join(self.colors))
		self.stdout.println("Available aliases: " + ", ".join(self.aliases.keys()))

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
		set_comment = None
		headers = self.helpers.analyzeRequest(message.getMessageInfo()).getHeaders()

		for h in headers:
			x = h.lower()
			# First check if we have the combined color and comment header
			if x.startswith("x-pentest:"):
				if ";" in x:
					color = x.split(":")[1].split(";")[0].strip()
					set_comment = ":".join(h.split(":")[1:]).split(";")[1].strip()
				else:
					color = x.split(":")[1].strip()
				if color in self.colors:
					set_color = color
				elif color in self.aliases:
					set_color = self.aliases[color]
				else:
					self.stderr.println("Unsupported color " + color + " found, available colors: " + ", ".join(self.colors + self.aliases.keys()))
			# If a color header is defined just set the color
			elif x.startswith("color:") or x.startswith("x-pentest-color:"):
				color = x.split(":")[1].strip()
				if color in self.colors:
					set_color = color
				elif color in self.aliases:
					set_color = self.aliases[color]
				else:
					self.stderr.println("Unsupported color " + color + " found, available colors: " + ", ".join(self.colors + self.aliases.keys()))
			# If a comment header is defined just set the comment
			elif x.startswith("comment:") or x.startswith("x-pentest-comment:"):
				set_comment = ":".join(h.split(":")[1:]).strip()
			elif self.automagically and set_comment is None and x.startswith("user-agent:"):
				# Check for autochrome UA
				if 'autochrome' in x:
					m = re.search(r'autochrome/([a-z]+)', x)
					if m and m.group(1):
						if m.group(1) in self.colors:
							set_color = m.group(1)
						elif m.group(1) in self.aliases:
							set_color = self.aliases[m.group(1)]
						else:
							self.stderr.println("Unsupported color " + m.group(1) + " found, available colors: " + ", ".join(self.colors + self.aliases.keys()))
				# Otherwise, use the User-Agent
				else: 
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
		if not set_comment is None:
			message.getMessageInfo().setComment(set_comment)

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
