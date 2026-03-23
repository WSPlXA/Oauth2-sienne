local revoke_ttl = tonumber(ARGV[1]) or 0
local token_found = 0
local introspection_deleted = 0

if KEYS[1] ~= "" and redis.call("EXISTS", KEYS[1]) == 1 then
    redis.call("HSET", KEYS[1], "revoked", "1")
    token_found = 1
end

if revoke_ttl > 0 then
    redis.call("SET", KEYS[2], "1", "EX", revoke_ttl)
else
    redis.call("SET", KEYS[2], "1")
end

if KEYS[3] ~= "" then
    introspection_deleted = redis.call("DEL", KEYS[3])
end

return { token_found, introspection_deleted }
