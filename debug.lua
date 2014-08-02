






function read_query( packet )
    if packet:byte() == proxy.COM_QUERY then
        local tk = require('proxy.tokenizer')
        local tokens = tk.tokenize(packet:sub(2))
        local tok =1
        print("--------------------------------\n")
        print("DB: "..proxy.connection.client.default_db.."\n")
        print("num_tokens "..#tokens .. "\n")
        print("Query: "..packet:sub(2).."\n")
        while tok <= #tokens do
        print(tokens[tok]['token_name'].." : "..tokens[tok]['text'].."\n")
        tok = tok+1
        end
    end
end

