UPDATE users
SET
    status = CASE WHEN status = 'locked' THEN 'active' ELSE status END,
    failed_login_count = 0,
    updated_at = ?
WHERE id = ?;
