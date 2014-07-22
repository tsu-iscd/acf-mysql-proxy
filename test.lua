
--Loading user and entities names and security labels (sec_labels) from the file
function init_sec_labels ()

print("Initialization of security labels\n")
local fr = io.open("users.txt","r")

c=0
for line in fr:lines() do
    for k, v in string.gmatch(line,"(%w+):(%d+)") do
            proxy.global.u[k]=tonumber(v)
    end
c=c+1
end

fr:close()
print("Number of loaded users: "..c.."\n")

local fre= io.open("ent.txt","r")

c=0
le=false
for line in fre:lines() do
le=false
print(line)
    
    -- Loading DB, Table, column names and sec_labels
    for dbn,tn,cn,v in string.gmatch(line,"(.+):(.+):(.+):(%d+)") do
        proxy.global.c[cn]={db=dbn,table=tn,label=tonumber(v)}
        c=c+1
        le=true
    end

    if le==false then
        -- Loading DB,Table names and sec_labels
        for dbn,tn,v in string.gmatch(line,"(.+):(.+):(%d+)") do
           proxy.global.t[tn]={db=dbn,label=tonumber(v)}
           c=c+1
           le=true
        end
    end

    if le==false then
        -- Loading DB names and sec_labels
        for dbn,v in string.gmatch(line,"(.+):(%d+)") do
            proxy.global.db[dbn]=tonumber(v)
            c=c+1
        end
    end
end

fre:close()

print("Number of loaded entities: "..c.."\n")

end

function set_error(errmsg)
    proxy.response = {
    type = proxy.MYSQLD_PACKET_ERR,
    errmsg = errmsg or "error"    
    }
end

function connect_server()

if not proxy.global.u then
    proxy.global.u={}
    proxy.global.db={}
    proxy.global.t={}
    proxy.global.c={}
    init_sec_labels()
    end

end

function user_sec_label()

for k,v in pairs(proxy.global.u) do
        if k == proxy.connection.client.username then
            return v
            end
    end

return -1
end

function ent_sec_label(ent_n)
        for k,v in pairs(proxy.global.t) do
           if k == ent_n then
               return v
           end
        end
     for k,v in pairs(proxy.global.db) do
         if k == ent_n then
             return v
         end
     end

return -1
end


function sel_check_access(tokens,tok)

while tok <= #tokens do

    if tokens[tok]['token_name'] ~= "TK_FUNCTION"  then
        if tokens[tok]['token_name'] == "TK_SQL_FROM" then
            while tok <= #tokens do
                tok = tok +1
                if tokens[tok]['token_name'] == 'TK_SQL_AS' then
                    tok=tok+1
                elseif tokens[tok]['token_name'] == 'TK_SQL_LITERAL' then


                    end
            --ul = user_sec_label()
            --el = ent_sec_label(tokens[tok+1]['text'])
            --print("Ent_l "..tokens[tok+1]['text'].."\n")
            --print("Lables u="..ul.." e="..el.."\n")
            if ul >= el then
                return tok+1,false
            else 
                return tok+1,true
            end
            end
        end
    else 
        return tok,false
    end
tok = tok +1

end

return tok,false

end

function ins_check_access(tokens,tok)

end

function upd_check_access(tokens,tok)

end

function del_check_access(tokens,tok)

end


function read_query( packet )
	if packet:byte() == proxy.COM_QUERY then
        local tk = require('proxy.tokenizer')
        local tokens = tk.tokenize(packet:sub(2))
        local tok =1
        print("num_tokens "..#tokens .. "\n")
        print("Query: "..packet:sub(2).."\n")
        while tok <= #tokens do
            print(tok)
        res = false
             if tokens[tok]['token_name'] == "TK_SQL_SELECT" then
                 tok,res = sel_check_access(tokens,tok)
             elseif res ==false and tok ~= #tokens and  tokens[tok]['token_name'] == "TK_SQL_INSERT" then
                 tok,res = ins_check_access(tokens,tok)
             elseif res == false and tok ~= #tokens and  tokens[tok]['token_name'] == "TK_SQL_UPDATE" then
                 tok,res = upd_check_access(tokens,tok)
             elseif res == false and tok ~= #tokens and  tokens[tok]['token_name'] == "TK_SQL_DELETE" then
                 tok,res = del_check_access()
             end
    
             if res == true then
                  set_error("Query ("..packet:sub(2)..") was blocked")
                  return proxy.PROXY_SEND_RESULT
             end
        tok = tok+1
        end
    end
end


