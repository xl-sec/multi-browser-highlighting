# Author: 	Emmanuel Law
# Version:	1.0
# License: 	MIT License

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IInterceptedProxyMessage
from burp import IContextMenuFactory

from javax.swing import JMenu, JMenuItem
from java.awt.event import ActionListener
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender,IProxyListener, IContextMenuFactory,ActionListener):
	def registerExtenderCallbacks( self, callbacks):
		# Keep a reference to our callbacks and helper object
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()

		self.stdout = PrintWriter(callbacks.getStdout(), True)
		self.stderr = PrintWriter(callbacks.getStderr(), True)

		# Keep Track of Browsers
		self.browsers = {}
		# Colors for different browsers
		self.colors = ["red", "blue", "pink", "green", "magenta", "cyan", "orange", "gray", "yellow"]
		self.aliases = {"purple": "magenta", "grey": "gray"}

		self.callbacks.setExtensionName("Multi-Browser Highlighting")
		self.enabled = False
		self.header_enabled = True
		self.useragent_enabled = True

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
			if self.header_enabled and x.startswith("x-pentest:"):
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
			elif self.header_enabled and (x.startswith("color:") or x.startswith("x-pentest-color:")):
				color = x.split(":")[1].strip()
				if color in self.colors:
					set_color = color
				elif color in self.aliases:
					set_color = self.aliases[color]
				else:
					self.stderr.println("Unsupported color " + color + " found, available colors: " + ", ".join(self.colors + self.aliases.keys()))
			# If a comment header is defined just set the comment
			elif self.header_enabled and (x.startswith("comment:") or x.startswith("x-pentest-comment:")):
				set_comment = ":".join(h.split(":")[1:]).strip()
			elif self.useragent_enabled and set_comment is None and x.startswith("user-agent:"):
				# Check for NCC autochrome UA
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
			if self.enabled:
				mymenu = JMenu("Multi-Browser Highlight (Running)")
				mymenu.add(JMenuItem("Click to disable", None, actionPerformed=lambda x: self.flip('enabled')))
				mymenu.add(JMenuItem("Base of HTTP headers: " + ("Enabled" if self.header_enabled else "Disabled"), None, actionPerformed=lambda x: self.flip('header_enabled')))
				mymenu.add(JMenuItem("Base of User-Agent: " + ("Enabled" if self.useragent_enabled else "Disabled"), None, actionPerformed=lambda x: self.flip('useragent_enabled')))
			else:
				mymenu = JMenu("Multi-Browser Highlight (Stopped)")
				mymenu.add(JMenuItem("Click to enable", None, actionPerformed=lambda x: self.flip('enabled')))
			return [mymenu]
		else:
			return None

	def flip(self, to_flip):
		if to_flip == 'enabled':
			self.enabled = not self.enabled	
		if to_flip == 'header_enabled':
			self.header_enabled = not self.header_enabled
		if to_flip == 'useragent_enabled':
			self.useragent_enabled = not self.useragent_enabled
