local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local comm = require "comm"

description = [[
Java Deserialization vulnerability scanner for OpeNMS webserver.

Detects vulnerabilities in versions prior to version 18.
]]

author = "Kendrick Lam"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery"}

---
-- @usage
-- nmap -sV --script opennms <host>
--
-- @output
-- PORT STATE SERVICE
-- |_opennms: OpenNMS server potentially vulnerable to Java Deserialization 
--


portrule = function(host, port)
	return (port.number == 1099 or port.service == "rmiregistry" or port.version.product == "Java RMI") and port.state == "open"
end

action = function(host, port, opts)
	local data = string.format("\x4a\x52\x4d\x49\x00\x02\x4b\x00\x00\x00\x00\x00\x00")
	local output = stdnse.output_table()
	local socket, response = comm.exchange(host.ip, port.number, data)
	if string.find(response, "N\x00\x0e") then
		return "OpenNMS server potentially vulnerable to Java Deserialization"
	end
end
