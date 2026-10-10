package tlsparse

import "testing"

// The examples are quoted from the JA4 specification's ALPN section
// (FoxIO-LLC/ja4, technical_details/JA4.md), not derived from this code.
func TestJA4ALPN(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"x", "xx"}, // a single character is both first and last
		{"", "00"},
		{"\xab", "ab"},
		{"\x20", "20"},
		{"\xab\xcd", "ad"},
		{"\x20\x61", "21"},
		{"\x30\xab", "3b"},
		{"\x61\x20", "60"},
		{"\x30\x31\xab\xcd", "3d"},
		{"\x30\xab\xcd\x31", "01"},
	}
	for _, c := range cases {
		if got := ja4ALPNOne(c.alpn); got != c.want {
			t.Errorf("ja4ALPNOne(%q) = %q, want %q", c.alpn, got, c.want)
		}
	}
	if got := ja4ALPN(nil); got != "00" {
		t.Errorf("ja4ALPN(nil) = %q, want 00", got)
	}
}

// Chrome 154 puts a GREASE value first in signature_algorithms and picks
// a new one per connection. JA4 must not change with it.
func TestJA4IgnoresGREASESignatureAlgorithms(t *testing.T) {
	ja4 := func(sigAlgs []uint16) string {
		s := pqcSpec()
		s.SigAlgs = sigAlgs
		ch, err := ParseClientHello(buildClientHello(s))
		if err != nil {
			t.Fatal(err)
		}
		return ch.JA4()
	}
	plain := ja4([]uint16{0x0403, 0x0804, 0x0401})
	for _, g := range []uint16{0x1a1a, 0xcaca} {
		if got := ja4([]uint16{g, 0x0403, 0x0804, 0x0401}); got != plain {
			t.Errorf("GREASE %#04x first in signature_algorithms changed JA4: %s, want %s", g, got, plain)
		}
	}
}

// ALPS codepoints as BoringSSL defines them (include/openssl/tls1.h).
func TestALPSExtensionNames(t *testing.T) {
	if got := ExtensionName(17613); got != "application_settings" {
		t.Errorf("ExtensionName(17613) = %q, want application_settings", got)
	}
	if got := ExtensionName(17513); got != "application_settings_old" {
		t.Errorf("ExtensionName(17513) = %q, want application_settings_old", got)
	}
}
