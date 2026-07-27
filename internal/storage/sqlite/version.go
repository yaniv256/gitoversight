package sqlite

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	major int
	minor int
	patch int
}

func ParseVersion(value string) (Version, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid sqlite version %q", value)
	}
	parsed := [3]int{}
	for index, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return Version{}, fmt.Errorf("invalid sqlite version %q", value)
		}
		parsed[index] = number
	}
	return Version{major: parsed[0], minor: parsed[1], patch: parsed[2]}, nil
}

func mustVersion(value string) Version {
	version, err := ParseVersion(value)
	if err != nil {
		panic(err)
	}
	return version
}

func (v Version) LessThan(other Version) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch) }
