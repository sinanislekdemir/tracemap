package history

import (
	"context"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleEntry(label string) Entry {
	return Entry{
		Kind:    "scan",
		Label:   label,
		MaxHops: 30,
		Traces: []Trace{
			{
				Label:     label,
				Kind:      "A",
				IP:        "1.1.1.1",
				TargetIP:  "1.1.1.1",
				TargetGeo: &Geo{Lat: 1, Lon: 2, City: "One", Country: "OO", ASN: "AS1", Resolved: true},
				Hops: []Hop{
					{Hop: 1, IP: "10.0.0.1"},
					{Hop: 2, IP: "1.1.1.1", RTTMs: 12.5, IsTarget: true, Geo: &Geo{Lat: 1, Lon: 2, Resolved: true}},
				},
			},
			{Label: label, Kind: "AAAA", IP: "2001:db8::1", Hops: []Hop{{Hop: 1}}},
		},
	}
}

func TestSaveListLoadRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := sampleEntry("example.com")
	id, err := store.Save(ctx, want)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if id == 0 {
		t.Fatal("Save returned id 0")
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d entries, want 1", len(list))
	}
	summary := list[0]
	if summary.ID != id || summary.Label != want.Label || summary.Kind != want.Kind {
		t.Errorf("summary = %+v, want id=%d label=%q kind=%q", summary, id, want.Label, want.Kind)
	}
	if summary.TraceCount != 2 {
		t.Errorf("TraceCount = %d, want 2", summary.TraceCount)
	}
	if summary.HopCount != 3 {
		t.Errorf("HopCount = %d, want 3", summary.HopCount)
	}
	if summary.CreatedAt == 0 {
		t.Error("CreatedAt was not stamped")
	}

	entries, err := store.Load(ctx, []int64{id})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Load returned %d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.MaxHops != want.MaxHops || len(got.Traces) != len(want.Traces) {
		t.Fatalf("entry = %+v, want maxHops=%d traces=%d", got, want.MaxHops, len(want.Traces))
	}
	if got.Traces[0].TargetGeo == nil || *got.Traces[0].TargetGeo != *want.Traces[0].TargetGeo {
		t.Errorf("target geo = %+v, want %+v", got.Traces[0].TargetGeo, want.Traces[0].TargetGeo)
	}
	if got.Traces[0].Hops[1].RTTMs != 12.5 || !got.Traces[0].Hops[1].IsTarget {
		t.Errorf("hop round-trip lost data: %+v", got.Traces[0].Hops[1])
	}
}

func TestListNewestFirst(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for i, label := range []string{"first", "second", "third"} {
		entry := sampleEntry(label)
		entry.CreatedAt = int64(1000 + i)
		if _, err := store.Save(ctx, entry); err != nil {
			t.Fatalf("Save(%s): %v", label, err)
		}
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"third", "second", "first"}
	for i, summary := range list {
		if summary.Label != want[i] {
			t.Errorf("list[%d] = %q, want %q", i, summary.Label, want[i])
		}
	}
}

func TestLoadSkipsUnknownAndEmpty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if entries, err := store.Load(ctx, nil); err != nil || len(entries) != 0 {
		t.Fatalf("Load(nil) = %v, %v; want empty", entries, err)
	}

	id, err := store.Save(ctx, sampleEntry("keep"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := store.Load(ctx, []int64{id, 9999})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != id {
		t.Errorf("Load with unknown id = %+v, want only id %d", entries, id)
	}
}

func TestDeleteAndClear(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	first, _ := store.Save(ctx, sampleEntry("first"))
	second, _ := store.Save(ctx, sampleEntry("second"))

	if err := store.Delete(ctx, first); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ctx, 12345); err != nil {
		t.Errorf("Delete unknown id: %v", err)
	}
	list, _ := store.List(ctx)
	if len(list) != 1 || list[0].ID != second {
		t.Fatalf("after delete list = %+v, want only %d", list, second)
	}

	if err := store.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	list, _ = store.List(ctx)
	if len(list) != 0 {
		t.Errorf("after clear list = %+v, want empty", list)
	}
}

func TestDisabledStore(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\"): %v", err)
	}
	if store != nil {
		t.Fatal("expected a nil store for an empty path")
	}

	ctx := context.Background()
	if _, err := store.Save(ctx, sampleEntry("x")); err == nil {
		t.Error("Save on disabled store should error")
	}
	if _, err := store.List(ctx); err == nil {
		t.Error("List on disabled store should error")
	}
	if entries, err := store.Load(ctx, []int64{1}); err != nil || len(entries) != 0 {
		t.Errorf("Load on disabled store = %v, %v; want empty", entries, err)
	}
}
