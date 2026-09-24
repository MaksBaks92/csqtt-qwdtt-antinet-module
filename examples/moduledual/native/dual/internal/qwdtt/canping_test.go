// SPDX-License-Identifier: GPL-3.0-or-later

package qwdtt

import "testing"

func TestCanPingQwdtt(t *testing.T) {
	cases := []struct {
		arg  string
		want string
	}{
		{"qwdtt://config?peer=1.2.3.4&hashes=abc&pass=x", "ok"},
		{"qwdtt://config?peer=1.2.3.4&hashes=abc\n/profile\n", "ok"},
		{"qwdtt://config?peer=1.2.3.4&pass=x", "no"},
		{"qwdtt://config?peer=1.2.3.4&pass=x\n/p\nstateblob", "ok"},
		{"wdtt://1.2.3.4:56000:51820:0:secret:hash1", "ok"},
		{"csqtt://nope", "no"},
		{"", "no"},
	}
	for _, tc := range cases {
		if got := canPingQwdtt(tc.arg); got != tc.want {
			t.Fatalf("canPingQwdtt(%q)=%q want %q", tc.arg, got, tc.want)
		}
		if got := Call("canping", tc.arg); got != tc.want {
			t.Fatalf("Call(canping,%q)=%q want %q", tc.arg, got, tc.want)
		}
	}
}
