--Set max_label parameter to each entity arrays (db,t,c)
function set_max_label()

max_label=0
    for kt,vt in pairs(proxy.global.t) do
        max_label = vt['label']

        for kc,vc in pairs(proxy.global.c) do

            if vc['db'] == vt['db'] and kt == vc['table'] and max_label<vc['label'] then

               max_label=vc['label']

            end

        end

        vt['max_label']=max_label
        print('T: '..kt..' Max_label: '..max_label..'\n')

    end

    for kd,vd in pairs(proxy.global.db) do

        max_label=vd['label']

        for kt,vt in pairs(proxy.global.t) do
        
            if kd == vt['db'] and max_label<vt['max_label'] then

                max_label=vt['max_label']

            end

        end

        vd['max_label']=max_label
        print('DB: '..kd..' Max_label: '..max_label..'\n')

    end
end

--Insert into array only unique elements
function set_insert(a,x)

    for i = 1, #a do
        if a[i] == x then
            return a
        end
    end

table.insert(a,x)

return a

end

--Insert into dictionary only unique elements
function set_insert(a,x,y)

    for k,v in pairs(a) do
        if k == x then
            return a
        end
    end

a[x]=y

return a

end

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
            proxy.global.db[dbn]={label=tonumber(v)}
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
    set_max_label()
    end

end

--Returns default DB value (i.e. after use command has been used)
function current_db()
    return proxy.connection.client.default_db
end

function user_sec_label()

for k,v in pairs(proxy.global.u) do
        if k == proxy.connection.client.username then
            return v
            end
    end

return -1
end

--ent_sec_label returns the label of the entity. 
--type=0(db), 1(table), 2(column)
function ent_sec_label(max,type,db_n,t_n,c_n)

    if type==2 then
        for k,v in pairs(proxy.global.c) do
            if k == c_n and v['db']==db_n and v['table']==t_n then
                return v['label']
            end
        end
    end
    
    if type==1 then
        for k,v in pairs(proxy.global.t) do
            if k == t_n and v['db']==db_n then
                if max==true then
                    return v['max_label']
                end
                return v['label']
            end
        end
    end

    if type==0 then
        for k,v in pairs(proxy.global.db) do
            if k == db_n then
                if max==true then
                    return v['max_label']
                end
                return v['label']
            end
        end
    end

return -1
end



--Core functions
--Access read. Check if subject has label >= than label of the object. 
--Return false in case of access is granted and true in case of access is not granted.
function access_read(sub_l, obj_l)

if sub_l>=obj_l then
    return false
end

return true

end

--Access write. If request is not complex (is_com=false) than check if subject label >= object label than grant access.
--If request is complex than check and deny access if entities (read) not > than entities (write).
function access_write(sub_l,w_obj_l,is_com,r_obj_l)

if is_com==false then

    if sub_l >=w_obj_l then
        return false
    end

else 

    if access_read(sub_l,r_obj_l)==false and r_obj_l<=w_obj_l and sub_l>=w_obj_l then
        return false
    end

end

return true

end

--Access append. If request is not complex (is_com=false) then check if request is complex then check and deny access if entities (read) not > than entities (write).
function access_append(sub_l,w_obj_l,is_com,r_obj_l)

if is_com==false then
    return false
else
    if access_read(sub_l,r_obj_l)==false and r_obj_l<=w_obj_l then
        return false
    end
end

return true

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


-- Check access to delete entry of the table.
function del_check_access(tokens,tok)

max_tokens = #tokens
while tok <= max_tokens do
    if tokens[tok]['token_name'] == "TK_SQL_FROM"  then
        tok = tok +1
        if tokens[tok]['token_name'] == 'TK_LITERAL' then
            el = 0
            if tok+2<=max_tokens then
                if tokens[tok+1]['token_name'] == 'TK_DOT' then
                    el = ent_sec_label(true,1,tokens[tok]['text'],tokens[tok+2]['text'],nil)
                end
            else
                el=ent_sec_label(true,1,current_db(),tokens[tok]['text'],nil)
                print("el = "..el.."\n")
            end


            ul = user_sec_label()
            --el = ent_sec_label(tokens[tok]['text'],true)
            print("Ent_l "..tokens[tok]['text'].."\n")
            print("Lables u="..ul.." e="..el.."\n")
            
            --if ul >= el then
                --return tok+1,false
            --else
                --return tok+1,true
            --end
            return tok+1,access_write(ul,el,false)    
        else
            return tok,true
        end
    end
tok = tok +1
end

return tok,false

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
                 tok,res = del_check_access(tokens,tok)
             end
    
             if res == true then
                  set_error("Query ("..packet:sub(2)..") was blocked")
                  return proxy.PROXY_SEND_RESULT
             end
        tok = tok+1
        end
    end
end


