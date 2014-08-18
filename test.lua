json = require("json")

local raw_json_text = json:encode({ 1, 2, 'fred', {first='mars',second='venus',third='earth'} })
local lua_v = json:decode(raw_json_text)
print(raw_json_text)
print(lua_v)
