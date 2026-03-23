if redis.call("EXISTS", KEYS[1]) == 0 then
    return -1
end

local old_revoked = redis.call("HGET", KEYS[1], "revoked")
local rotated_to = redis.call("HGET", KEYS[1], "rotated_to")
if old_revoked == "1" or (rotated_to and rotated_to ~= "") then
    return -2
end

local new_ttl = tonumber(ARGV[9]) or 0
local old_revoke_ttl = tonumber(ARGV[10]) or 0

redis.call("HSET", KEYS[1],
    "revoked", "1",
    "rotated_to", ARGV[2]
)

if old_revoke_ttl > 0 then
    redis.call("SET", KEYS[3], "1", "EX", old_revoke_ttl)
else
    redis.call("SET", KEYS[3], "1")
end

redis.call("HSET", KEYS[2],
    "client_id", ARGV[3],
    "user_id", ARGV[4],
    "subject", ARGV[5],
    "scopes_json", ARGV[6],
    "issued_at", ARGV[7],
    "expires_at", ARGV[8],
    "revoked", "0",
    "rotated_from", ARGV[1],
    "rotated_to", ""
)

if new_ttl > 0 then
    redis.call("EXPIRE", KEYS[2], new_ttl)
end

if KEYS[4] ~= "" then
    redis.call("SADD", KEYS[4], "refresh:" .. ARGV[2])
    if new_ttl > 0 then
        local user_set_ttl = redis.call("TTL", KEYS[4])
        if user_set_ttl < 0 or user_set_ttl < new_ttl then
            redis.call("EXPIRE", KEYS[4], new_ttl)
        end
    end
end

if KEYS[5] ~= "" then
    redis.call("SADD", KEYS[5], "refresh:" .. ARGV[2])
    if new_ttl > 0 then
        local client_set_ttl = redis.call("TTL", KEYS[5])
        if client_set_ttl < 0 or client_set_ttl < new_ttl then
            redis.call("EXPIRE", KEYS[5], new_ttl)
        end
    end
end

return 1
