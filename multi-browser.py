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
		# keep a reference to our callbacks and helper object
		self._callbacks=callbacks
		self._helpers=callbacks.getHelpers()

		self.stdout = PrintWriter(callbacks.getStdout(), True)

		# Keep Track of Browsers
		self._browser={}
		# Colors for different browsers
		self.colors=["red", "blue", "pink", "green", "magenta", "cyan", "gray", "yellow"]

		self._callbacks.setExtensionName("Multi-Browser Highlighting")
		self.isEnabled=False

		#IExtensionHelpers helpers = callbacks.getHelpers()
		callbacks.registerProxyListener(self)
		callbacks.registerContextMenuFactory(self)
		return

	def processProxyMessage(self, messageIsRequest, message):
		if self.isEnabled == False:
			return
		if messageIsRequest == False:
			return
		browser_agent=None
		headers=self._helpers.analyzeRequest(message.getMessageInfo()).getHeaders()

		for x in headers:
			# if a color header is defined just set the color
			if x.lower().startswith("color:"):
				color=x.lower()[6:].strip()
				if color in self.colors:
                                    message.getMessageInfo().setHighlight(color)
                                    return
                        # check for autochrome UA
			elif x.lower().startswith("user-agent:") and 'autochrome' in x.lower():
                            m = re.search(r'autochrome/([a-z]+)', x.lower())
                            if m and m.group(1):
                                color = m.group(1)
				if color in self.colors:
                                    message.getMessageInfo().setHighlight(color)
                                    return

			# otherwise, use the user-agent
			elif x.lower().startswith("user-agent:"):
				browser_agent=x

		if browser_agent not in self._browser:
			self._browser[browser_agent]={"id":len(self._browser)+1, "agent":browser_agent, "color":self.colors.pop()}


		self.stdout.println(self._browser[browser_agent]["agent"])
		message.getMessageInfo().setHighlight(self._browser[browser_agent]["color"])

	def createMenuItems(self, invocation):
		if invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY:
			mymenu=[]
			if self.isEnabled:
				item=JMenuItem("Multi-Browser Highlight (Running): Click to Disable ")
			else:
				item=JMenuItem("Multi-Browser Highlight (Stopped): Click to Enable ")
			item.addActionListener(self)
			mymenu.append(item)
			return mymenu

		else:
			return None
	def actionPerformed(self, actionEvent):
		self.isEnabled= not self.isEnabled


