package authority

import "encoding/hex"

const (
	EnvironmentDev        = "dev"
	EnvironmentProduction = "production"
)

// ValidEnvironment accepts the exact logical environment spellings carried by
// signed A9 authority and Gate 8 wrappers.
func ValidEnvironment(value string) bool {
	return value == EnvironmentDev || value == EnvironmentProduction
}

// ValidInstallationID accepts exactly 32 bytes encoded as 64 lowercase
// hexadecimal characters. Prefixes, separators, uppercase, and padding are
// deliberately not canonical.
func ValidInstallationID(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil &&
		len(decoded) == 32 &&
		hex.EncodeToString(decoded) == value
}

// ValidAccountIncarnationID accepts the canonical UUID text spelling:
// 8-4-4-4-12 lowercase hexadecimal digits separated by hyphens. Braces, URN
// prefixes, compact spellings, and uppercase are rejected. This validator
// constrains canonical representation; UUID version and variant remain issuer
// semantics rather than bridge-side transformations.
func ValidAccountIncarnationID(value string) bool {
	if len(value) != 36 ||
		value[8] != '-' ||
		value[13] != '-' ||
		value[18] != '-' ||
		value[23] != '-' {
		return false
	}
	compact := make([]byte, 0, 32)
	for index := range len(value) {
		switch index {
		case 8, 13, 18, 23:
			continue
		default:
			compact = append(compact, value[index])
		}
	}
	decoded, err := hex.DecodeString(string(compact))
	return err == nil &&
		len(decoded) == 16 &&
		hex.EncodeToString(decoded) == string(compact)
}
