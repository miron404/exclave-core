package reality

import (
	"fmt"
	"strconv"
	"strings"
)

// DefaultClientVersion is the compatibility version advertised in REALITY's
// authentication header. It is independent of Exclave's own release number.
const DefaultClientVersion = "26.11.9"

func ParseClientVersion(value string) ([3]byte, error) {
	var version [3]byte
	if value == "" {
		value = DefaultClientVersion
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return version, fmt.Errorf("REALITY version must contain three numbers from 0 to 255")
	}
	for i, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return version, fmt.Errorf("invalid REALITY version %q", value)
		}
		n, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return version, fmt.Errorf("invalid REALITY version %q: %w", value, err)
		}
		version[i] = byte(n)
	}
	return version, nil
}
