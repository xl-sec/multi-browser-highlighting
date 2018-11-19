

# Note: This plugin has moved and is now mantained [here](https://github.com/libnex/burp-multi-browser-highlighting/) 

  
  
  
  
  

# Multi-Browser Highlighting

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Version](https://img.shields.io/badge/Version-1.0-blue.svg)

A simple Burp plugin that highlights and comments the Proxy history to differentiate requests made by different users. The plugin can highlight the requests automatically based on the User-Agent or specified by specific HTTP headers. 

During pentesting, I often have two or more different browsers opened to test issues such as role matrix, as well as to show how requests in one client might affect another. It is however hard to visualize which requests were made by which browser within the proxy histroy. Hence this plug-in was created to help visualize how different requests interleave with one another.

When enabled, the plugin acts automatically by assigning a color per browser User-Agent (compatible with [autochrome](https://github.com/nccgroup/autochrome)). You can also set the color and comment with the `X-Pentest` header by separating the color and comments with a semicolon (;). Available colors are: red, blue, pink, green, magenta, cyan, orange, gray, yellow

Example:
* `X-Pentest: red`
* `X-Pentest: blue; Admin`
* `X-Pentest: ; Just a comment`
* `X-Pentest-Color: yellow`
* `X-Pentest-Comment: Just a comment`

It is designed to be **non-intrusive**, so highlighting is disabled by default. Turn it on in the Proxy context menu only when you need it.

## Screenshots

Requests from three different browsers show how their traffic interleave:

<img width="942" alt="screen shot 2017-07-13 at 1 59 28 pm" src="https://user-images.githubusercontent.com/11704508/28147891-8c9355a8-67d7-11e7-8fea-12505a71b404.png">

Toggle it on/off within context menu:

<img width="522" alt="screen shot 2017-07-13 at 3 03 19 pm" src="https://user-images.githubusercontent.com/11704508/28148687-7332c7ce-67dc-11e7-9c64-d949c259284b.png" width=25%>

## Author

Emmanuel Law
