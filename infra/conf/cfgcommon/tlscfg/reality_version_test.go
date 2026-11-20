package tlscfg

import (
	"encoding/base64"
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/transport/internet/reality"
)

func TestREALITYVersionFromJSONConfig(t *testing.T) {
	for _, value := range []string{"", "25.5.16", "26.11.9", "99.99.99"} {
		input := REALITYConfig{PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Version: value}
		built, err := input.Build()
		if err != nil {
			t.Fatal(err)
		}
		config := built.(*reality.Config)
		if config.Version != value {
			t.Fatalf("version lost: %q != %q", config.Version, value)
		}
		if _, err := reality.ParseClientVersion(config.Version); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"99.99.256", "26.11", "invalid"} {
		input := REALITYConfig{PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Version: value}
		if _, err := input.Build(); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
