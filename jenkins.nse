local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local comm = require "comm"

description = [[
Java Deserialization vulnerability scanner for Jenkins webserver.

Detects vulnerabilities in versions prior to 1.638 and 1.625.2.
]]

author = "Kendrick Lam"

license = "SRLabs"

categories = {"discovery"}

---
-- @usage
-- nmap -sV --script jenkins <host>
--
-- @output
-- PORT STATE SERVICE
-- |_jenkins: Java Deserialization vulnerability found in Jenkins webserver
--

portrule = function(host, port)
	return (port.number == 8080 or port.service == "http" or port.service == "http-proxy" or port.version.product == "Jetty") and port.state == "open"
end

action = function(host, port)
	local header = "\x00\x14\x50\x72\x6F\x74\x6F\x63\x6F\x6C\x3A\x43\x4C\x49\x2D\x63\x6F\x6E\x6E\x65\x63\x74"
	local data = string.format("GET / HTTP/1.1\nHost: %s:%s\nUser Agent: Java/1.8.0_45-internal\nContent-Length: 164\n\nCookie: JSESSIONID.538d6690=node01d0507a13952daqv1qyjkjqk18.node0; JSESSIONID.4c8cbccd=tf2hgf07w6ei8ynx6zsillrp; screenResolution=1920x1019 Connection: close", host.ip, port.number)
	local output = stdnse.output_table()
	local socket, response = comm.exchange(host.ip, port.number, data)
	if string.match(response, "X%-%Jenkins%-%CLI%-%Port: %d*") ~= nil then
		i = string.match(response, "X%-%Jenkins%-%CLI%-%Port: %d*" )
		local cli_port = string.match(i, "%d+")
		local sock, resp = comm.exchange(host.ip, cli_port, header, {lines=2})
		if string.find(resp, "rO0AB") then
			return "Java Deserialization vulnerability found in Jenkins webserver."
		end
	end
end

