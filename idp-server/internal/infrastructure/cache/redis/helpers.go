package redis

import (
	"strconv"
	"time"
)

func durationSeconds(ttl time.Duration) int64 {
	seconds := int64(ttl / time.Second)
	if ttl > 0 && seconds == 0 {
		return 1
	}
	return seconds
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func parseBoolString(value string) bool {
	return value == "1" || value == "true"
}

func parseInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}
