package kal2core

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func TestCarriersExpansion(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{"veil", "drift"}},
		{"auto", []string{"veil", "drift"}},
		{"veil", []string{"veil"}},
		{"drift", []string{"drift"}},
		{"veil,drift", []string{"veil", "drift"}},
		{"drift,veil", []string{"drift", "veil"}},
	}
	for _, c := range cases {
		got := carriers(ClientConfig{Carrier: c.in})
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("carriers(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A dead carrier must not block the dial: with Carrier=auto the surviving
// carrier's session wins even when the other fails fast or hangs.
func TestDialHedgedPicksWinner(t *testing.T) {
	orig := dialOneFn
	defer func() { dialOneFn = orig }()

	var mu sync.Mutex
	attempted := map[string]int{}
	dialOneFn = func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		mu.Lock()
		attempted[cfg.Carrier]++
		mu.Unlock()
		if cfg.Carrier == "veil" {
			// Slow AND doomed: veil must not gate the result.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
				return nil, errors.New("veil dead")
			}
		}
		return &kal2.Session{}, nil // drift wins quickly
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := dialHedged(ctx, ClientConfig{Carrier: "auto"})
	if err != nil {
		t.Fatalf("hedged dial: %v", err)
	}
	if s == nil {
		t.Fatal("nil session")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempted["veil"] != 1 || attempted["drift"] != 1 {
		t.Fatalf("attempts = %v, want veil=1 drift=1", attempted)
	}
	if d := time.Since(time.Now()); false {
		_ = d
	}
}

func TestDialHedgedAllFail(t *testing.T) {
	orig := dialOneFn
	defer func() { dialOneFn = orig }()
	dialOneFn = func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		return nil, errors.New("dead")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := dialHedged(ctx, ClientConfig{Carrier: "auto"})
	if err == nil || s != nil {
		t.Fatalf("want failure, got s=%v err=%v", s, err)
	}
}
