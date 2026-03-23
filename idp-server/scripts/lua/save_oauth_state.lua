if redis.call("EXISTS", KEYS[1]) == 1 then
    return 0
end

local ttl = tonumber(ARGV[5]) or 0

redis.call("HSET", KEYS[1],
    "client_id", ARGV[1],
    "redirect_uri", ARGV[2],
    "session_id", ARGV[3],
    "created_at", ARGV[4]
)

if ttl > 0 then
    redis.call("EXPIRE", KEYS[1], ttl)
end

return 1
