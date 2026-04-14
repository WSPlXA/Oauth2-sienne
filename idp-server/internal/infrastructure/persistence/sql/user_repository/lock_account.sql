UPDATE users
SET status = CASE WHEN status = 'active' THEN 'locked' ELSE status END,
    updated_at = ?
WHERE id = ?;
