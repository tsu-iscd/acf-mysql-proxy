
package.cpath = package.cpath .. ";/usr/lib/i386-linux-gnu/lua/5.1/?.so"


function comment_tokenizer(tok_text)

local ctk = require('proxy.tokenizer')
local comment_toks  = ctk.tokenize(tok_text)
local ctok = 1

print("TK_COMMENT LEX ----------------BEGIN------ "..tok_text.."\n")
while ctok <= #comment_toks do
    if comment_toks[ctok]['token_name'] == 'TK_COMMENT' then
        comment_tokenizer(comment_toks[ctok]['text'])
    end
    print(".. "..comment_toks[ctok]['token_name'].." : "..comment_toks[ctok]['text'].."\n")
    ctok = ctok+1
end
print("TK_COMMENT LEX ----------------END------\n")

end

function read_query( packet )
    if packet:byte() == proxy.COM_QUERY then
        local parse = require('proxy.parser')
        local tk = require('proxy.tokenizer')
        local tokens  = tk.tokenize(packet:sub(2))
        --local toks = tk.normalize(tokens)
        local tok =1
        print("--------------------------------\n")
        print("DB: "..proxy.connection.client.default_db.."\n")
        print("num_tokens "..#tokens .. "\n")
        print("Query: "..packet:sub(2).."\n")

        tbls = parse.get_tables(tokens)
        for k,v in pairs(tbls) do
            local db,t = k:match("([^.]+).([^.]+)")
            print('db: '..db..'\ntables: '..t..'\nsql: '..v..'\n')
        end
        --print("Toks: "..toks.."\n")
        while tok <= #tokens do
            
            if tokens[tok]['token_name'] == 'TK_COMMENT' then
                print("begin")
                local driver = require "luasql.mysql"
                local env = assert(driver.mysql())
                local con = assert(env:connect("test","root","asd123"))
                print(env,con)
                --for id, str in rows(con, "select * from asd") do
                --    print (string.format ("%s: %s", id, str))
                --end
                cur,err = con:execute([[show databases]])
                
                row = cur:fetch ({}, "a")
                while row do
                    print(string.format("Name: %s", row.Database))
                    row = cur:fetch (row, "a")
                end
                cur:close()
                con:close()
                env:close()
                print("end")
                -- comment_tokenizer(tokens[tok]['text'])
            else
                print(tokens[tok]['token_name'].." : "..tokens[tok]['text'].."\n")
            end
            tok = tok+1
        end
        proxy.queries:append(1,packet,{resultset_is_needed = true})
        return proxy.PROXY_SEND_QUERY
    end
end

function read_query_result(inj)
    local res = assert(inj.resultset)
    --for row in inj.resultset.rows do
    --    print("Query  returned: "..row[1])
    --end
   
   --print(res)
    
    if inj.resultset.query_status == proxy.MYSQLD_PACKET_OK then
        print("OK")
    else
        print("ERR")
    end 
    --return proxy.PROXY_SEND_RESULT

end



