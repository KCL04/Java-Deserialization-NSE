local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Java Deserialization vulnerability scanner for JBoss webserver.

Detects vulnerabilities in versions prior to version 7.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery"}

---
-- @usage 
-- nmap -sV --script jboss <host>
--
-- @output
-- PORT	STATE SERVICE
-- |_jboss: Java Deserialization vulnerability found in JBoss webserver
--

portrule = function(host, port)
	return (port.number == 8080 or port.service == "http" or port.service == "http-proxy" or port.version.product == "Apache Tomcat/Coyote JSP engine") and port.state == "open"
end

action = function(host, port)
	local url2 = '/invoker/JMXInvokerServlet'
	local res = http.get(host, port, url2)
	if string.find(res.body, "^\xAC\xED\x00\x05") then
		return "Java Deserialization Vulnerability found in JBoss Webserver"
	end
end

