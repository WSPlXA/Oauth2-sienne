SELECT
    id,
    code,
    target_url,
    click_count,
    expires_at,
    last_access_at,
    created_at,
    updated_at
FROM short_urls
WHERE code = ?
LIMIT 1
