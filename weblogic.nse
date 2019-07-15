local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local comm = require "comm"

description = [[
Java Deserialization vulnerability scanner for Oracle WebLogic Server.

Detects vulnerabilities in versions 12c and older.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery"}

---
-- @usage
-- nmap -sV --script weblogic <host>
--
-- @output
-- PORT	STATE SERVICE
-- |_weblogic: Java Deserialization Vulnerability found in Oracle WebLogic Server
--

portrule = function(host, port)
	return (port.number == 7001 or port.service == "afs3-callback" or port.service == "http" or port.version.product == "Oracle WebLogic admin httpd" or port.service == "http-proxy") and port.state == "open"
end

action = function(host, port, opts)
	local data = string.format("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:%s\n\n", port.number)
	local output = stdnse.output_table()
	local socket, response = comm.exchange(host.ip, port.number, data)
	if string.find(response, "HELO") then 
		return "Java Deserialization vulnerability found in Oracle WebLogic Server"
	end
end

