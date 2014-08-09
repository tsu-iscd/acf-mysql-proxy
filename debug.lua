






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
            print('tables: '..k..'\nsql: '..v..'\n')
        end
        --print("Toks: "..toks.."\n")
        while tok <= #tokens do
            print(tokens[tok]['token_name'].." : "..tokens[tok]['text'].."\n")
            tok = tok+1
        end
    end
end

