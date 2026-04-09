UPDATE users
SET
    password_hash = ?,
    failed_login_count = 0,
    updated_at = ?
WHERE id = ?;
