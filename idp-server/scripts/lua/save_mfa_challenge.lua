-- Save or update MFA challenge hash with bitmask state and optimistic CAS.
--
-- KEYS:
--   KEYS[1] = challenge hash key
--   KEYS[2] = challenge state key (packed u32 state + u32 version)
--
-- ARGV:
--   ARGV[1]  = challenge_id
--   ARGV[2]  = user_id
--   ARGV[3]  = subject
--   ARGV[4]  = username
--   ARGV[5]  = ip_address
--   ARGV[6]  = user_agent
--   ARGV[7]  = return_to
--   ARGV[8]  = redirect_uri
--   ARGV[9]  = mfa_mode
--   ARGV[10] = push_status
--   ARGV[11] = push_code
--   ARGV[12] = approver_user_id
--   ARGV[13] = decided_at
--   ARGV[14] = passkey_session_json
--   ARGV[15] = expires_at
--   ARGV[16] = ttl seconds
--   ARGV[17] = next state mask (u32)
--   ARGV[18] = expected state version (u32), -1 means skip CAS
--
-- Return:
--   {1, next_ver}   success
--   {-2, cur_ver}   CAS conflict
--   {-3, cur_ver}   invalid transition
local ttl = tonumber(ARGV[16]) or 0
local next_state = tonumber(ARGV[17]) or 0
local expected_ver = tonumber(ARGV[18]) or -1

local cur_pair = redis.call("BITFIELD", KEYS[2], "GET", "u32", 0, "GET", "u32", 32)
local cur_state = tonumber(cur_pair[1]) or 0
local cur_ver = tonumber(cur_pair[2]) or 0

-- migration fallback for records that still keep state in hash fields.
if cur_ver == 0 then
    cur_ver = tonumber(redis.call("HGET", KEYS[1], "state_ver") or "0")
end
if cur_state == 0 then
    local old_mask = tonumber(redis.call("HGET", KEYS[1], "state_mask") or "0")
    if old_mask > 0 then
        cur_state = old_mask
    else
        local hash_mode = redis.call("HGET", KEYS[1], "mfa_mode") or ""
        local hash_push = redis.call("HGET", KEYS[1], "push_status") or ""
        local hash_passkey = redis.call("HGET", KEYS[1], "passkey_session_json") or ""
        if hash_mode == "passkey_totp_fallback" then
            cur_state = bit.bor(cur_state, 2)
        elseif hash_mode == "push_totp_fallback" then
            cur_state = bit.bor(cur_state, 4)
        end
        if hash_push == "approved" then
            cur_state = bit.bor(cur_state, 8)
        elseif hash_push == "denied" then
            cur_state = bit.bor(cur_state, 16)
        end
        if hash_passkey ~= "" then
            cur_state = bit.bor(cur_state, 32)
        end
        if cur_state ~= 0 then
            cur_state = bit.bor(cur_state, 1)
        end
    end
end

if expected_ver >= 0 and cur_ver ~= expected_ver then
    return {-2, cur_ver}
end

-- bit layout:
-- 1   live
-- 2   mode passkey
-- 4   mode push
-- 8   push approved
-- 16  push denied
-- 32  passkey session bound
local bit_live = 1
local bit_mode_passkey = 2
local bit_mode_push = 4
local bit_push_approved = 8
local bit_push_denied = 16
local bit_passkey_bound = 32

if bit.band(next_state, bit_live) == 0 then
    return {-3, cur_ver}
end

-- push/passkey mode must be exclusive.
if bit.band(next_state, bit_mode_push) ~= 0 and bit.band(next_state, bit_mode_passkey) ~= 0 then
    return {-3, cur_ver}
end

-- non-push mode cannot carry push decision bits.
local push_decision = bit.band(next_state, bit_push_approved + bit_push_denied)
if bit.band(next_state, bit_mode_push) == 0 and push_decision ~= 0 then
    return {-3, cur_ver}
end

-- approved and denied cannot be true at the same time.
if push_decision == (bit_push_approved + bit_push_denied) then
    return {-3, cur_ver}
end

-- once terminal decision is reached, decision bits cannot be rewritten.
local cur_terminal = bit.band(cur_state, bit_push_approved + bit_push_denied)
if cur_terminal ~= 0 and cur_terminal ~= push_decision then
    return {-3, cur_ver}
end

local next_ver = cur_ver + 1
if next_ver > 4294967295 then
    next_ver = 1
end

redis.call("HSET", KEYS[1],
    "challenge_id", ARGV[1],
    "user_id", ARGV[2],
    "subject", ARGV[3],
    "username", ARGV[4],
    "ip_address", ARGV[5],
    "user_agent", ARGV[6],
    "return_to", ARGV[7],
    "redirect_uri", ARGV[8],
    "mfa_mode", ARGV[9],
    "push_status", ARGV[10],
    "push_code", ARGV[11],
    "approver_user_id", ARGV[12],
    "decided_at", ARGV[13],
    "passkey_session_json", ARGV[14],
    "expires_at", ARGV[15]
)

redis.call("BITFIELD", KEYS[2],
    "SET", "u32", 0, next_state,
    "SET", "u32", 32, next_ver
)

if ttl > 0 then
    redis.call("EXPIRE", KEYS[1], ttl)
    redis.call("EXPIRE", KEYS[2], ttl)
end

return {1, next_ver}
