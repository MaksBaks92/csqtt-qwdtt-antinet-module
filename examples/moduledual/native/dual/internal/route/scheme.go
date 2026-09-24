// Package route picks csqtt vs qwdtt from the AntiNet LINK= value.
package route

import (
	"fmt"
	"strings"
)

type Scheme string

const (
	SchemeCSQTT Scheme = "csqtt"
	SchemeQWDTT Scheme = "qwdtt"
)

// FromLink returns the protocol scheme embedded in a raw LINK (csqtt://… or qwdtt://…).
// For multi-line moduleCall args (canping: link\nprofileDir\nstateBlob) only the first line is used.
func FromLink(link string) (Scheme, error) {
	link = strings.TrimSpace(link)
	if i := strings.IndexByte(link, '\n'); i >= 0 {
		link = strings.TrimSpace(link[:i])
	}
	low := strings.ToLower(link)
	switch {
	case strings.HasPrefix(low, "csqtt://"):
		return SchemeCSQTT, nil
	case strings.HasPrefix(low, "qwdtt://"), strings.HasPrefix(low, "wdtt://"):
		// wdtt:// is legacy alias accepted by upstream qWDTT normalize.
		return SchemeQWDTT, nil
	default:
		return "", fmt.Errorf("unsupported LINK scheme (want csqtt:// or qwdtt://): %q", trunc(link, 64))
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
