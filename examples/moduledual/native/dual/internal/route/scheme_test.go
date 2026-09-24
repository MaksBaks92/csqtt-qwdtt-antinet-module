package route

import "testing"

func TestFromLink(t *testing.T) {
	cases := []struct {
		in   string
		want Scheme
		ok   bool
	}{
		{"csqtt://x", SchemeCSQTT, true},
		{"CSQTT://x", SchemeCSQTT, true},
		{"qwdtt://peer", SchemeQWDTT, true},
		{"wdtt://legacy", SchemeQWDTT, true},
		{"https://nope", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, err := FromLink(tc.in)
		if tc.ok && err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: expected error", tc.in)
		}
		if tc.ok && got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}
