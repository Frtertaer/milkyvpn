package main

import (
	"reflect"
	"testing"
)

// Drop-ins override the main unit's ExecStart — the panel must read the
// effective (last non-empty) line or it pins stale flags/binary.
func TestParseExecStart(t *testing.T) {
	for _, tc := range []struct {
		name string
		cat  string
		want []string
	}{
		{
			"main only",
			"# /etc/systemd/system/kal2.service\n[Service]\nExecStart=/opt/kal2/srv -listen :1\n",
			[]string{"/opt/kal2/srv", "-listen", ":1"},
		},
		{
			"drop-in resets and overrides",
			"# /etc/systemd/system/kal2.service\n[Service]\nExecStart=/opt/kal2/v5 -x\n\n# /etc/systemd/system/kal2.service.d/90-rtc.conf\n[Service]\nExecStart=\nExecStart=/opt/kal2/v7 -rtc :2\n",
			[]string{"/opt/kal2/v7", "-rtc", ":2"},
		},
		{
			"later drop-in wins over earlier drop-in",
			"ExecStart=/a -old\nExecStart=\nExecStart=/b -mid\nExecStart=/c -new\n",
			[]string{"/c", "-new"},
		},
		{
			"blank reset alone yields nil",
			"ExecStart=/a -old\nExecStart=\n",
			nil,
		},
		{
			"no ExecStart",
			"[Service]\nEnvironment=X=1\n",
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseExecStart(tc.cat); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
