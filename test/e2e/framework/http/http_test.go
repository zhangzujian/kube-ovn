package http

import (
	"encoding/json"
	"testing"
)

func TestLoop(t *testing.T) {
	records, err := Loop(nil, "test", "http://172.18.0.2:31745/metrics", "GET", 3, 100, 500, 200)
	if err != nil {
		t.Fatal(err)
	}

	for _, record := range records {
		buf, _ := json.MarshalIndent(record, "", "  ")
		t.Log(string(buf))
	}
}
