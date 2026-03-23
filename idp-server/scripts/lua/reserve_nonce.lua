local ttl = tonumber(ARGV[2]) or 0

if ttl > 0 then
    local ok = redis.call("SET", KEYS[1], ARGV[1], "EX", ttl, "NX")
    if ok then
        return 1
    end
    return 0
end

local ok = redis.call("SET", KEYS[1], ARGV[1], "NX")
if ok then
    return 1
end

return 0
