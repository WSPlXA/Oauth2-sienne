local counter_ttl = tonumber(ARGV[1]) or 0
local threshold = tonumber(ARGV[2]) or 0
local lock_ttl = tonumber(ARGV[3]) or 0

local count = redis.call("INCR", KEYS[1])

if count == 1 and counter_ttl > 0 then
    redis.call("EXPIRE", KEYS[1], counter_ttl)
end

local locked = 0
if KEYS[2] ~= "" and threshold > 0 and lock_ttl > 0 and count >= threshold then
    redis.call("SET", KEYS[2], "1", "EX", lock_ttl)
    locked = 1
end

local ttl = redis.call("TTL", KEYS[1])
return { count, ttl, locked }
