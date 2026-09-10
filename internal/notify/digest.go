package notify

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Digest accumulates matched items per (recipient npub, rule) pair for
// DeliverySummary rules and flushes them as a single message on Interval.
// DeliveryImmediate items bypass the digest entirely — the caller sends them
// straight away.
type Digest struct {
	Interval time.Duration
	Send     func(recipientNpub, body string) error

	mu      sync.Mutex
	pending map[string][]Item // key: recipient npub
}

// NewDigest builds a Digest that flushes every interval via send.
func NewDigest(interval time.Duration, send func(recipientNpub, body string) error) *Digest {
	return &Digest{Interval: interval, Send: send, pending: map[string][]Item{}}
}

// Add queues item for the next flush to recipientNpub.
func (d *Digest) Add(recipientNpub string, item Item) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending[recipientNpub] = append(d.pending[recipientNpub], item)
}

// Flush sends and clears every recipient's pending queue. It returns the
// first send error encountered, after attempting every recipient (a failure
// for one recipient must not drop another's digest).
func (d *Digest) Flush() error {
	d.mu.Lock()
	batch := d.pending
	d.pending = map[string][]Item{}
	d.mu.Unlock()

	var firstErr error
	for npub, items := range batch {
		if len(items) == 0 {
			continue
		}
		if err := d.Send(npub, FormatDigest(items)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("notify: digest send to %s: %w", npub, err)
		}
	}
	return firstErr
}

// Run flushes on Interval until ctx-like stop channel closes. Callers that
// need context cancellation should close stop from a context.Done() watcher.
func (d *Digest) Run(stop <-chan struct{}) {
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_ = d.Flush()
		case <-stop:
			_ = d.Flush()
			return
		}
	}
}

// FormatDigest renders a batch of items as a single human-readable message,
// most severe first.
func FormatDigest(items []Item) string {
	sorted := make([]Item, len(items))
	copy(sorted, items)
	sortBySeverityDesc(sorted)

	var b strings.Builder
	fmt.Fprintf(&b, "%d notice(s):\n", len(sorted))
	for _, it := range sorted {
		fmt.Fprintf(&b, "- [%s/%s] %s\n", it.Class, it.Severity, it.Summary)
	}
	return b.String()
}

// FormatImmediate renders a single item as an immediate DM body.
func FormatImmediate(item Item) string {
	return fmt.Sprintf("[%s/%s] %s", item.Class, item.Severity, item.Summary)
}

func sortBySeverityDesc(items []Item) {
	// Insertion sort: batches are small (per-recipient, per-interval), and
	// this keeps equal-severity items in arrival order (stable).
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && severityRank(items[j].Severity) > severityRank(items[j-1].Severity); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
