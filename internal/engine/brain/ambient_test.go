package brain

import "testing"

func hostWith(addr string, attention float64, surprise string) HostSnapshot {
	return HostSnapshot{ScopeID: "s1", Address: addr, Attention: attention, Surprise: surprise}
}

func TestAmbientProjection_RanksByAttentionAndBudgets(t *testing.T) {
	hosts := []HostSnapshot{
		hostWith("10.0.0.1", 0.1, ""),
		hostWith("10.0.0.2", 0.9, ""),
		hostWith("10.0.0.3", 0.5, ""),
	}
	kept, omitted := AmbientProjection(hosts, 2)
	if len(kept) != 2 || omitted != 1 {
		t.Fatalf("want 2 kept / 1 omitted, got %d/%d", len(kept), omitted)
	}
	if kept[0].Address != "10.0.0.2" || kept[1].Address != "10.0.0.3" {
		t.Errorf("expected highest-attention first: %s, %s", kept[0].Address, kept[1].Address)
	}
}

func TestAmbientProjection_AnomalyChannelAlwaysIncluded(t *testing.T) {
	hosts := []HostSnapshot{
		hostWith("10.0.0.1", 0.9, ""),
		hostWith("10.0.0.2", 0.8, ""),
		hostWith("10.0.0.3", 0.0, "address reused by a different host"), // low attention but anomalous
	}
	kept, omitted := AmbientProjection(hosts, 2)
	// budget 2 would drop the anomaly by attention, but it must be kept.
	var hasAnomaly bool
	for _, h := range kept {
		if h.Address == "10.0.0.3" {
			hasAnomaly = true
		}
	}
	if !hasAnomaly {
		t.Fatalf("anomalous host must be included despite low attention; kept=%+v", kept)
	}
	if omitted != 0 {
		t.Errorf("the 3rd host is the anomaly (kept), so 0 omitted, got %d", omitted)
	}
}

func TestAmbientProjection_NoBudgetKeepsAll(t *testing.T) {
	hosts := []HostSnapshot{hostWith("a", 1, ""), hostWith("b", 2, "")}
	kept, omitted := AmbientProjection(hosts, 0)
	if len(kept) != 2 || omitted != 0 {
		t.Fatalf("budget<=0 keeps all: got %d/%d", len(kept), omitted)
	}
}

func TestAmbientProjection_Empty(t *testing.T) {
	kept, omitted := AmbientProjection(nil, 5)
	if kept != nil || omitted != 0 {
		t.Fatalf("empty input → empty output")
	}
}
