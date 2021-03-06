--Load DTE policy (domains, types and privileges).
function load_dte_policy()
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
        local robj = Entity:extends{db=vt['db'],tbl=kt, type=1,sec_label=max_label}
        vt['max_label_obj'] = robj
        print('T: '..kt..' Max_label: '..max_label..'\n')

    end

    for kd,vd in pairs(proxy.global.db) do

        max_label=vd['label']

        for kt,vt in pairs(proxy.global.t) do
        
            if kd == vt['db'] and max_label<vt['max_label'] then

                max_label=vt['max_label']

            end

        end

        local robj = Entity:extends{db=kd, type=0,sec_label=max_label}
        vd['max_label']=max_label
        vd['max_label_obj']=robj
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

-- Save policy to ent.json file
function save_policy()
print(json.encode(lua_v))
local fer = io.open("ent.json","w")
fer:write(json.encode(lua_v))
fer:close()

end

--Loading user and entities names and security labels (sec_labels) from the file
function init_sec_labels()

print("Initialization of security labels\n")


local cu = 0
local ce = 0

for k,v in pairs(lua_v) do
    if k == "users" then
        for un, l in pairs(v) do
            local subj = Entity:extends{user=un,sec_label=tonumber(l)}
            proxy.global.u[un]={label=tonumber(l),obj=subj}
            cu=cu+1
        end
    end

    if k == "dbs" then
        for dbn,at in pairs(v) do
            for n,l in pairs(at) do
                if n=="label" then
                    local robj = Entity:extends{db=dbn,type=0,sec_label=tonumber(l)}
                    proxy.global.db[dbn]={label=tonumber(l),obj=robj}
                    ce=ce+1
                end
                if n=="max_label" then
                    local robj = Entity:extends{db=dbn,type=0,sec_label=tonumber(l)}
                    proxy.global.db[dbn]={max_label=tonumber(l),obj=robj}
                end
                if n=="tables" then
                    for tn,tat in pairs(l) do
                        for tl,tv in pairs(tat) do
                            if tl == "label" then
                                local robj = Entity:extends{db=dbn,tbl=tn, type=1,sec_label=tonumber(tv)}
                                proxy.global.t[tn]={db=dbn,label=tonumber(tv),obj=robj}
                                ce=ce+1
                            end
                            if tl == "max_label" then
                                local robj = Entity:extends{db=dbn,tbl=tn, type=1,sec_label=tonumber(tv)}
                                proxy.global.t[tn]={db=dbn,max_label=tonumber(tv),obj=robj}
                            end
                            if tl == "columns" then
                                for cn,cv in pairs(tv) do
                                    local robj = Entity:extends{db=dbn,tbl=tn,clmn=cn, type=2,sec_label=tonumber(cv)}
                                    proxy.global.c[cn]={db=dbn,table=tn,label=tonumber(cv),obj=robj}
                                    ce=ce+1
                                end
                            end
                        end
                    end
                end
            end
        end
    end

end

print("Number of loaded users: "..cu.."\n")
print("Number of loaded entities: "..ce.."\n")

end


function set_error(errmsg)
    proxy.response = {
    type = proxy.MYSQLD_PACKET_ERR,
    errmsg = errmsg or "error"    
    }
end


function connect_server()

json = require('json')
local fer = io.open("ent.json","rb")
ent_json_raw = fer:read("*all")
fer:close()
lua_v = json.decode(ent_json_raw)

local LCS = require 'LCS'

Entity = LCS.class.abstract{sec_label=nil}


function Entity:init(slbl,user)
self.sec_label = slbl
self.user=user
self.db = nil
self.tbl = nil
self.clmn = nil
end

function Entity:describe()
    if self.user ~= nil then
        return self.user
    elseif self.db ~= nil then
        return self.db
    elseif self.tbl ~= nil then
        return self.tbl
    elseif self.clmn ~= nil then
        return self.clmn
    end
    return 'Nil'
end

Entity.__eq = function (o,t)
    return o.sec_label == t.sec_label
end

Entity.__lt = function (o,t)
    return o.sec_label < t.sec_label
end

Entity.__le = function (o,t)
    return o.sec_label <= t.sec_label
end

Entity.__gt = function (o,t)
    return o.sec_label > t.sec_label
end

Entity.__ge = function (o,t)
    return o.sec_label >= t.sec_label
end

if not proxy.global.u then
    proxy.global.u={}
    proxy.global.db={}
    proxy.global.t={}
    proxy.global.c={}
    proxy.global.domain={}
    proxy.global.type={}
    proxy.global.priv={}
    proxy.global.tmp={}
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
            return v['obj']
        end
    end

return -1
end

--Returns security label (number) of the user
function user_sec_label_num()

    for k,v in pairs(proxy.global.u) do
        if k == proxy.connection.client.username then
            return v['label']
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
                return v['obj']
            end
        end
    end
    
    if type==1 then
        for k,v in pairs(proxy.global.t) do
            if k == t_n and v['db']==db_n then
                if max==true then
                    --local robj = Entity:extends{db=v['db'],tbl=k, type=1,sec_label=v['max_label']}
                    return v['max_label_obj']
                end
                return v['obj']
            end
        end
    end

    if type==0 then
        for k,v in pairs(proxy.global.db) do
            if k == db_n then
                if max==true then
                    --local robj = Entity:extends{db=k, type=0,sec_label=v['max_label']}
                    return v['max_label_obj']
                end
                return v['obj']
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
            end


            ul = user_sec_label()
            print("Lables u="..ul.sec_label.." e="..el.sec_label.."\n")
            
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
        if tokens[tok]['token_name'] == "TK_SQL_SELECT" or tokens[tok]['token_name'] == "TK_SQL_INSERT" or tokens[tok]['token_name'] == "TK_SQL_UPDATE" or tokens[tok]['token_name'] == "TK_SQL_DELETE" or tokens[tok]['token_name'] == "TK_SQL_REPLACE" then
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
                print("User_label = "..ul.sec_label.."\nEnt_label = "..el.sec_label.."\nDB = "..db.." Table = "..tab)
                res=access_read(ul,el)
                if res == true then
                    return res
                end
            end 
        end
        if find==false then 
            local el=ent_sec_label(false,1,db,tab)
            print("User_label = "..ul.sec_label.."\nEnt_label = "..el.sec_label.."\nDB = "..db.." Table = "..tab)
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
                    print("User_label = "..ul.sec_label.."\nEnt_label = "..el.sec_label.."\nDB = "..db.." Table = "..tab)
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
                print("No columns. User_label = "..ul.sec_label.."\nEnt_label = "..el.sec_label.."\nDB = "..db.." Table = "..tab)
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
                    print("User_label = "..ul.sec_label.."\nEnt_label = "..el.sec_label.."\nDB = "..db.." Table = "..tab)
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
                print("No columns. User_label = "..ul.sec_label.."\nEnt_label = "..el.sec_label.."\nDB = "..db.." Table = "..tab)
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

--Check access to execute routine (procedure or function). DTE policy is used.
function call_check_access(tokens)

local max_tokens = #tokens
local tok=2
while tok<=max_tokens do

    if tokens[tok]['token_name'] == "TK_FUNCTION" then

        local domain=''
        for k,v in pairs(proxy.global.domain) do
            if v == proxy.connection.client.username then
                print("Domain name: "..k)
                domain = k
            end
        end

        local type_n=''
        for k,v in pairs(proxy.global.type) do
            if v == tokens[tok]['text'] then
                print("Type name: "..k)
                type_n = k
            end
        end

        for k,v in pairs(proxy.global.priv) do
            if v['domain'] == domain and v['type'] == type_n then
                print("Access: "..k)
                if k:upper() == "EXECUTE" then
                    return false
                end
            end
        end

    end

tok=tok+1

end

return true;

end

--Check access to execute handler operator. 
function handler_check_access(tokens)

local max_tokens = #tokens
local tok=1
local res = false

if max_tokens < 3 then
    return res
end

while tok<max_tokens do
    tok=tok+1

    if tokens[tok].text:upper() == "OPEN" then
        local db_h = ''
        local tbl_h = ''
        if tokens[tok-1].token_name == "TK_LITERAL" then
            tbl_h = tokens[tok-1].text
            if tokens[tok-2]['token_name'] == "TK_DOT" then
                db_h = tokens[tok-3].text
            else
                db_h = current_db()
            end
        end
        local ul = user_sec_label()
        local el=ent_sec_label(true,1,db_h,tbl_h)
        res = access_read(ul,el)
        return res
    end

end

return res

end

--Check access to execute LOAD XML and LOAD DATA INFILE operators. 
function load_check_access(tokens)

local max_tokens = #tokens
local tok=1
local res = true
local file_name = ''
local db_name = ''
local table_name = ''

if max_tokens < 3 then
    return res
end

while tok<max_tokens and db_name == '' and table_name == '' do
    tok=tok+1

    if tokens[tok]['token_name'] == "TK_SQL_INFILE" and tokens[tok+1]['token_name'] == "TK_STRING" then
        file_name = tokens[tok+1].text
        print('File name: '..file_name)
    end

    if tokens[tok]['token_name'] == "TK_SQL_TABLE" then
        if tokens[tok+1].token_name == "TK_LITERAL" then
            if tok+2>=max_tokens then
                db_name = current_db()
                table_name = tokens[tok+1].text
            else
                if tokens[tok+2]['token_name'] == "TK_DOT" then
                    db_name = tokens[tok+1].text
                    table_name = tokens[tok+3].text
                else
                    db_name = current_db()
                    table_name = tokens[tok+1].text
                end
            end
        end
    end

end


local domain=''
for k,v in pairs(proxy.global.domain) do
    if v == proxy.connection.client.username then
        print("Domain name: "..k)
        domain = k
    end
end

local type_n=''
local wc_db = db_name..".*"
local wc_db_tb = db_name.."."..table_name
for k,v in pairs(proxy.global.type) do
    if v == wc_db_tb or v==wc_db then
        print("Type name: "..k)
        type_n = k
    end
end

for k,v in pairs(proxy.global.priv) do
    if v['domain'] == domain and v['type'] == type_n then
        print("Access: "..k)
        if k:upper() == "LOAD_FROM_FILE" then
            local ul = user_sec_label()
            local el=ent_sec_label(true,1,db_name,table_name)
            res = access_write(ul,el,false)
            return res
        end
    end
end


return res

end


function create_check_access(tokens)
local max_tokens = #tokens
local tok=1
local res = true
local file_name = ''
local db_name = ''
local table_name = ''

if max_tokens < 3 then
    return res
end

while tok < max_tokens do
    tok=tok+1
    if tokens[tok]["token_name"] == "TK_SQL_DATABASE" or tokens[tok]['token_name'] == "TK_SQL_SCHEMA" then
        while tok < max_tokens and tokens[tok]["token_name"] ~= "TK_LITERAL" do
            tok = tok+1
        end
        if tokens[tok]["token_name"] ~= "TK_LITERAL" then
            return res
        end
        local lbl = user_sec_label_num()
        local dbn = tokens[tok]["text"]
        proxy.global.tmp[proxy.connection.server.thread_id]=dbn
        local robj = Entity:extends{db=dbn,type=0,sec_label=lbl}
        proxy.global.db[dbn]={label=lbl,obj=robj}
        res = false
        print("Database "..tokens[tok]["text"].." can be created with label "..lbl.."\n")
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
        elseif tokens[tok]['token_name'] == "TK_SQL_INSERT" or tokens[tok]['token_name'] == "TK_SQL_REPLACE" then
            res = ins_check_access(tokens)
        elseif tokens[tok]['token_name'] == "TK_SQL_UPDATE" then
            res = upd_check_access(tokens)
        elseif tokens[tok]['token_name'] == "TK_SQL_CALL" then
            res = call_check_access(tokens)
        elseif tokens[tok]['token_name'] == "TK_SQL_LOAD" then
            res = load_check_access(tokens)
        elseif tokens[tok]['token_name'] == "TK_LITERAL" then
            if tokens[tok].text:upper() == "HANDLER" then
                res = handler_check_access(tokens)
            end
        elseif tokens[tok]['token_name'] == "TK_SQL_CREATE" then
            if tokens[tok+1]['token_name'] == "TK_SQL_DATABASE" or tokens[tok+1]['token_name'] == "TK_SQL_SCHEMA" then
                res = create_check_access(tokens)
                if res == false then
                    proxy.queries:append(proxy.connection.server.thread_id,packet,{resultset_is_needed = true})
                    return proxy.PROXY_SEND_QUERY
                end
            end
        end

        if res == true then
            set_error("Query ("..packet:sub(2)..") was blocked")
            return proxy.PROXY_SEND_RESULT
        end
    end
end



function read_query_result(inj)
    if inj.id == proxy.connection.server.thread_id then
        local res = assert(inj.resultset)
        if inj.resultset.query_status == proxy.MYSQLD_PACKET_OK then
            local lbl = user_sec_label_num()
            local tmp_lbl = {label=lbl,max_label=lbl,tables={}}
            lua_v["dbs"][proxy.global.tmp[proxy.connection.server.thread_id]]=tmp_lbl
            save_policy()
            proxy.global.tmp[proxy.connection.server.thread_id] = nil
            print("OK. New policy is saved.")
        else
            print("DB can't be created")
        end
    end
    
end

