-- custom.nse
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Extracts the HTML title from a web server.
]]

author = "Your Name"
license = "Same as Nmap"

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")
    if response.status and response.body then
        local title = response.body:match("<title>(.-)</title>")
        if title then
            return stdnse.format_output(true, ("Title: %s"):format(title))
        end
    end
    return "No title found"
end