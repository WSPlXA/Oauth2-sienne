local ttl = tonumber(ARGV[11]) or 0

redis.call("HSET", KEYS[1],
    "user_id", ARGV[2],
    "subject", ARGV[3],
    "acr", ARGV[4],
    "amr_json", ARGV[5],
    "ip", ARGV[6],
    "user_agent", ARGV[7],
    "authenticated_at", ARGV[8],
    "expires_at", ARGV[9],
    "status", ARGV[10]
)

if ttl > 0 then
    redis.call("EXPIRE", KEYS[1], ttl)
end

redis.call("SADD", KEYS[2], ARGV[1])

if ttl > 0 then
    local set_ttl = redis.call("TTL", KEYS[2])
    if set_ttl < 0 or set_ttl < ttl then
        redis.call("EXPIRE", KEYS[2], ttl)
    end
end

return 1
