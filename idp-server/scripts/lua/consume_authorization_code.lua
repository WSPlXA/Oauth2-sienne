local consumed_ttl = tonumber(ARGV[1]) or 0

if redis.call("EXISTS", KEYS[1]) == 0 then
    return { -1 }
end

if redis.call("EXISTS", KEYS[2]) == 1 then
    return { -2 }
end

local consumed = redis.call("HGET", KEYS[1], "consumed")
if consumed == "1" then
    if consumed_ttl > 0 then
        redis.call("SET", KEYS[2], "1", "EX", consumed_ttl)
    else
        redis.call("SET", KEYS[2], "1")
    end
    return { -2 }
end

redis.call("HSET", KEYS[1], "consumed", "1")

if consumed_ttl > 0 then
    redis.call("SET", KEYS[2], "1", "EX", consumed_ttl)
else
    redis.call("SET", KEYS[2], "1")
end

local data = redis.call("HGETALL", KEYS[1])
local response = { 1 }

for i = 1, #data do
    response[#response + 1] = data[i]
end

return response
