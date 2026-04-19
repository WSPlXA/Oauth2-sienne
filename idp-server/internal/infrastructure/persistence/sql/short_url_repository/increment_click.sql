UPDATE short_urls
SET
    click_count = click_count + 1,
    last_access_at = CURRENT_TIMESTAMP
WHERE id = ?
