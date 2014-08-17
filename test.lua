local json = require "json"

local te =  io.open("te.json","r")
local raw_json = te:read("*all")
print(raw_json)
local lua_v = json.decode( raw_json )

for k,v in pairs(lua_v) do
    print(k)
end

te:close()
