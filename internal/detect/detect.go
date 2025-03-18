package detect_vuln

import (
	"errors"
	"strconv"
	"strings"
)

// parseVersion converts a version string (e.g. "1.5.0") to a slice of integers.
func parseVersion(v string) ([]int, error) {
	parts := strings.Split(v, ".")
	var nums []int
	for _, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, errors.New("invalid version: " + v)
		}
		nums = append(nums, n)
	}
	return nums, nil
}

// CompareVersions compares two version strings.
// Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
func CompareVersions(v1, v2 string) (int, error) {
	nums1, err := parseVersion(v1)
	if err != nil {
		return 0, err
	}
	nums2, err := parseVersion(v2)
	if err != nil {
		return 0, err
	}
	maxLen := len(nums1)
	if len(nums2) > maxLen {
		maxLen = len(nums2)
	}
	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(nums1) {
			n1 = nums1[i]
		}
		if i < len(nums2) {
			n2 = nums2[i]
		}
		if n1 < n2 {
			return -1, nil
		} else if n1 > n2 {
			return 1, nil
		}
	}
	return 0, nil
}

// IsVulnerable checks if pkgVersion satisfies the given constraint.
// This simple implementation supports only constraints of the form "< 2.0.0".
func IsVulnerable(pkgVersion, constraint string) (bool, error) {
	constraint = strings.TrimSpace(constraint)
	if strings.HasPrefix(constraint, "<") {
		target := strings.TrimSpace(constraint[1:])
		cmp, err := CompareVersions(pkgVersion, target)
		if err != nil {
			return false, err
		}
		return cmp == -1, nil
	}
	return false, errors.New("unsupported constraint: " + constraint)
}
