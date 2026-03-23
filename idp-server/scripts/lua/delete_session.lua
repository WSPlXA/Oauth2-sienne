local deleted_session = redis.call("DEL", KEYS[1])
local removed_index = redis.call("SREM", KEYS[2], ARGV[1])

if redis.call("SCARD", KEYS[2]) == 0 then
    redis.call("DEL", KEYS[2])
end

return { deleted_session, removed_index }
