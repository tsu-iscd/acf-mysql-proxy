--Load DTE policy (domains, types and privileges).
function load_dte_policy()
local json = require("json")

local te =  io.open("dte.json","r")
local raw_json = te:read("*all")
local lua_v = json.decode( raw_json )

for k,v in pairs(lua_v) do
    if k == "domains" then
        for d,n in pairs(v) do
            proxy.global.domain[d]=n
            print("Domain: "..d.." Name: "..n)
        end
    end
    if k == "types" then
        for t,n in pairs(v) do
            proxy.global.type[t]=n
            print("Type: "..t.." Name: "..n)
        end
    end
    if k == "privileges" then
        for p,dt in pairs(v) do
            for d,t in pairs(dt) do
                proxy.global.priv[p]={domain=d,type=t}
                print("Priv: "..p.." Domain: "..d.." Type: "..t)
            end
        end 
    end
end

te:close()

end

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

--Creates a dictinary which includes a tree of entities in the query
function normilize_entities(dbs,tables,tables_alias,columns,columns_alias)
res={}
    if #tables_alias ==0 and #coulmns_alias == 0 then
        if #dbs == 0 then
            res[current_db()]={}
        end
    end
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
    proxy.global.domain={}
    proxy.global.type={}
    proxy.global.priv={}
    init_sec_labels()
    set_max_label()
    load_dte_policy()
    end

end

--Returns default DB value (i.e. after use command has been used)
function current_db()
    return proxy.connection.client.default_db
end

--Returns security label of the user
function user_sec_label()

    for k,v in pairs(proxy.global.u) do
        if k == proxy.connection.client.username then
            return v
        end
    end

return -1
end

--Returns the array of column names. Args: db name and table name.
function columns_arr(dbn,tabn)

    local colsn = {}
    for k,v in pairs(proxy.global.c) do
        if v['db']==dbn and v['table']==tabn then
            table.insert(colsn,k)
        end
    end

return colsn
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
            print("Ent_l "..tokens[tok]['text'].."\n")
            print("Lables u="..ul.." e="..el.."\n")
            
            return tok+1,access_write(ul,el,false)    
        else
            return tok,true
        end
    end
tok = tok +1
end

return tok,false

end

--Returns an array of query and sub-queries.
function sub_query_tokenize(tokens)

    local queries={}
    local qn=0
    local c=1
    for tok=1,#tokens do
        if tokens[tok]['token_name'] == "TK_SQL_SELECT" or tokens[tok]['token_name'] == "TK_SQL_INSERT" or tokens[tok]['token_name'] == "TK_SQL_UPDATE" or tokens[tok]['token_name'] == "TK_SQL_DELETE" then
            qn=qn+1
            c=1
            queries[qn]={}
        end
        queries[qn][c]=tokens[tok]
        c=c+1
    end

return queries
end

--Searching for columns in the query.
--Returns an array: {<name_of_the_column>:<true|false>}. True if column in query.
function find_columns(tokens,dbn,tabn)

    local clms = columns_arr(dbn,tabn)
    local res = {}
    if #clms==0 then
        return res
    end

    for tok=1, #tokens-1 do
        print('Find_columns '..tokens[tok]['token_name'])
        if tokens[tok]['token_name']=='TK_LITERAL' then
            for i=1,#clms do
               print(clms[i])
               if tokens[tok]['text'] == clms[i] then
                   res[clms[i]]=true
               end
            end
        elseif tokens[tok]['token_name']=='TK_STAR' then
            for i=1, #clms do
                res[clms[i]]=true
            end
        elseif tokens[tok]['token_name']=='TK_LITERAL' and tokens[tok+1]['token_name']=='TK_EQ' then
            for i=1,#clms do
                print(clms[i])
                if tokens[tok]['text'] == clms[i] then
                   res[clms[i]]=true
                end
            end
        end
    end

return res

end




--Searching for columns in the update query.
--Returns an array: {<name_of_the_column>:<true|false>}. True if column in query.
function find_columns_upd(tokens,dbn,tabn)

    local clms = columns_arr(dbn,tabn)
    local res = {}
    if #clms==0 then
        return res
    end

    for tok=1, #tokens-1 do
        print('Find_columns_upd '..tokens[tok]['token_name'])
        if tokens[tok]['token_name']=='TK_LITERAL' and tokens[tok+1]['token_name'] == 'TK_EQ' then
            for i=1,#clms do
               print(clms[i])
               if tokens[tok]['text'] == clms[i] then
                   res[clms[i]]=true
               end
            end
        end
    end

return res

end


-- Check access to select entries of the table.
function sel_check_access(tokens)

local parse = require('proxy.parser')
local sq=sub_query_tokenize(tokens)
local res=false

for t=1,#sq do
    local tbls = parse.get_tables(sq[t])
    for k,v in pairs(tbls) do
        local db,tab = k:match("([^.]+).([^.]+)")
        local ul=user_sec_label()
        local clms = find_columns(sq[t],db,tab)
        local find = false
        for c,fl in pairs(clms) do
            print('Column name = '..c)
            if fl==true then
                find=true
                local el=ent_sec_label(true,2,db,tab,c)
                print("User_label = "..ul.."\nEnt_label = "..el.."\nDB = "..db.." Table = "..tab)
                res=access_read(ul,el)
                if res == true then
                    return res
                end
            end 
        end
        if find==false then 
            local el=ent_sec_label(false,1,db,tab)
            print("User_label = "..ul.."\nEnt_label = "..el.."\nDB = "..db.." Table = "..tab)
            res = access_read(ul,el)
            if res == true then
                return res
            end
        end       
    end
end

return res

end

--Check access to execute insert command.
function ins_check_access(tokens)

local parse = require('proxy.parser')
local sq=sub_query_tokenize(tokens)
local w_obj_l = 0
local ul=user_sec_label()
local res = false

for t=1,#sq do
    local tbls = parse.get_tables(sq[t])
    for k,v in pairs(tbls) do
        local db,tab = k:match("([^.]+).([^.]+)")
        local clms = find_columns(sq[t],db,tab)
        local find = false
        for c,fl in pairs(clms) do
            if fl==true then
                find=true
                local el=ent_sec_label(true,2,db,tab,c)
                if #sq>1 and w_obj_l==0 and t == 1 then
                    print("User_label = "..ul.."\nEnt_label = "..el.."\nDB = "..db.." Table = "..tab)
                    res=access_append(ul,el,false)
                    w_obj_l=el
                elseif #sq == 1 then
                    res=access_append(ul,el,false)
                elseif #sq>1 and t>1 then
                    res=access_append(ul,w_obj_l,true,el)
                end
                if res == true then
                    return res
                end
            end
        end 
        if find==false then 
            local el=ent_sec_label(false,1,db,tab)
            if #sq>1 and w_obj_l==0 and t == 1 then
                print("No columns. User_label = "..ul.."\nEnt_label = "..el.."\nDB = "..db.." Table = "..tab)
                res = access_append(ul,el,false)
                w_obj_l = el
            elseif #sq == 1 then
                print('Sq==1')
                res = access_append(ul,el,false)
            elseif #sq>1 and t>1 then
                print('El == '..el)
                res = access_append(ul,w_obj_l,true,el)
            end
            if res == true then
                return res
            end
        end
                    
    end
end

return res

end

--Check access to execute update command.
function upd_check_access(tokens)

local parse = require('proxy.parser')
local sq=sub_query_tokenize(tokens)
local w_obj_l = 0
local ul=user_sec_label()
local res = false

for t=1,#sq do
    local tbls = parse.get_tables(sq[t])
    for k,v in pairs(tbls) do
        local db,tab = k:match("([^.]+).([^.]+)")
        local clms = find_columns_upd(sq[t],db,tab)
        local find = false
        for c,fl in pairs(clms) do
            if fl==true then
                find=true
                local el=ent_sec_label(true,2,db,tab,c)
                if #sq>1 and w_obj_l==0 and t == 1 then
                    print("User_label = "..ul.."\nEnt_label = "..el.."\nDB = "..db.." Table = "..tab)
                    res=access_write(ul,el,false)
                    w_obj_l=el
                elseif #sq == 1 then
                    res=access_write(ul,el,false)
                elseif #sq>1 and t>1 then
                    res=access_write(ul,w_obj_l,true,el)
                end
                if res == true then
                    return res
                end
            end
        end 
        if find==false then 
            local el=ent_sec_label(false,1,db,tab)
            if #sq>1 and w_obj_l==0 and t == 1 then
                print("No columns. User_label = "..ul.."\nEnt_label = "..el.."\nDB = "..db.." Table = "..tab)
                res = access_write(ul,el,false)
                w_obj_l = el
            elseif #sq == 1 then
                print('WSq==1')
                res = access_write(ul,el,false)
            elseif #sq>1 and t>1 then
                print('WEl == '..el)
                res = access_write(ul,w_obj_l,true,el)
            end
            if res == true then
                return res
            end
        end
                    
    end
end

return res

end

function read_query( packet )
	if packet:byte() == proxy.COM_QUERY then
        local tk = require('proxy.tokenizer')
        local tokens = tk.tokenize(packet:sub(2))
        local tok =1
        print("num_tokens "..#tokens .. "\n")
        print("Query: "..packet:sub(2).."\n")

        local res=false

        print(tokens[tok]['token_name'])
        if tokens[tok]['token_name'] == "TK_SQL_DELETE" then
            tok,res = del_check_access(tokens,tok)
        elseif tokens[tok]['token_name'] == "TK_SQL_SELECT" then
            res = sel_check_access(tokens)
        elseif tokens[tok]['token_name'] == "TK_SQL_INSERT" then
            res = ins_check_access(tokens)
        elseif tokens[tok]['token_name'] == "TK_SQL_UPDATE" then
            res = upd_check_access(tokens)
        end

        if res == true then
            set_error("Query ("..packet:sub(2)..") was blocked")
            return proxy.PROXY_SEND_RESULT
        end
    end
end

