package reality

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestClientVersion(t *testing.T) {
	for value, want := range map[string][3]byte{
		"": {26, 11, 9}, "26.11.9": {26, 11, 9}, "25.5.16": {25, 5, 16},
		"99.99.99": {99, 99, 99}, "0.0.0": {}, "255.255.255": {255, 255, 255},
	} {
		got, err := ParseClientVersion(value)
		if err != nil || got != want {
			t.Fatalf("%q: got %v, %v; want %v", value, got, err, want)
		}
	}
	for _, value := range []string{"26", "26.11", "26.11.9.1", "256.1.1", "-1.0.0", "+1.0.0", "1..3", "1.2.3 ", "a.1.2"} {
		if _, err := ParseClientVersion(value); err == nil {
			t.Fatalf("accepted invalid version %q", value)
		}
	}
}

func TestClientVersionSurvivesProtobuf(t *testing.T) {
	data, err := proto.Marshal(&Config{Version: "99.99.99"})
	if err != nil {
		t.Fatal(err)
	}
	var config Config
	if err := proto.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	got, err := ParseClientVersion(config.Version)
	if err != nil || got != [3]byte{99, 99, 99} {
		t.Fatalf("version lost in security config: %v, %v", got, err)
	}
}
