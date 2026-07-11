// This file (nftcidrset.go) mirrors the CIDR ranges of every "ipcidr"
// behavior rule-provider (subscriptions/files) into a pair of pre-existing
// nftables sets so that downstream PBR (policy-based routing) rules can
// match on them, in addition to the DNS-resolved IPs handled by nftset.go
// in this same package.
//
// The sets must be created externally (e.g. by OpenWrt init scripts):
//
//	nft add table inet clash
//	nft 'add set inet clash pbrcidr4 { type ipv4_addr; flags interval; }'
//	nft 'add set inet clash pbrcidr6 { type ipv6_addr; flags interval; }'
//
// Unlike nftset.go (which adds individually resolved IPs one at a time),
// this file always does a full atomic drop+refill of both sets: rule
// -provider content isn't additive across reloads, so the only correct
// mirror is "replace with exactly what the providers currently contain".
package nft

import (
	"context"
	"net/netip"
	"sort"
	"sync"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/nftables"
)

const (
	cidrSetName4 = "pbrcidr4"
	cidrSetName6 = "pbrcidr6"

	cidrBatchSize = 512
)

// cidrProvider is optionally implemented by the Strategy() value of a
// RuleProvider whose Behavior() is P.IPCIDR (currently *ipcidrStrategy in
// rules/provider, which is unexported — this interface lets us type-assert
// its Strategy() any without importing that package).
type cidrProvider interface {
	Foreach(f func(prefix netip.Prefix) bool)
}

// ruleLister is optionally implemented by the Strategy() value of a
// RuleProvider whose Behavior() is P.Classical (currently
// *classicalStrategy in rules/provider). A classical rule-set is a mixed
// bag of rule types (DOMAIN, IP-CIDR, PROCESS-NAME, ...) parsed into
// C.Rule values already — we pick out the C.IPCIDR ones and recover their
// netip.Prefix from Payload(), which every C.Rule already exposes.
type ruleLister interface {
	Rules() []C.Rule
}

var (
	mu     sync.Mutex
	cancel context.CancelFunc

	lastHash utils.HashType

	subscribeOnce sync.Once

	// writeMu serializes replace() calls: nftables Flush() transactions from
	// two concurrent runs can interleave in the kernel (one's FlushSet racing
	// the other's SetAddElements), which manifests as "file exists" errors
	// and a set left empty. Only one replace() may be in flight at a time.
	writeMu sync.Mutex
)

// Update triggers an asynchronous re-scan of every ipcidr rule-provider and,
// if the resulting CIDR set actually changed, an atomic drop+refill of the
// nftables sets. Safe to call concurrently and repeatedly: an in-flight run
// is cancelled and replaced by a fresh one rather than allowed to race it.
//
// The first call also subscribes to tunnel.RuleUpdateCallback, so that any
// later rule-provider load/reload (including a brand new subscription's
// first fetch) re-triggers Update on its own. Must be called at least once
// before rule providers are initialized (see hub/executor.updateRules,
// which runs before loadProvider(cfg.RuleProviders)) so the subscription is
// already in place for that first load.
func Update() {
	subscribeOnce.Do(func() {
		tunnel.Tunnel.RuleUpdateCallback().Register(func(P.RuleProvider) { Update() })
	})

	mu.Lock()
	if cancel != nil {
		cancel()
	}
	ctx, c := context.WithCancel(context.Background())
	cancel = c
	mu.Unlock()

	go run(ctx)
}

func run(ctx context.Context) {
	set4 := cidr.NewIpCidrSet()
	set6 := cidr.NewIpCidrSet()

	// add ignores individual errors: a bad prefix was already validated by
	// its source (rule-provider parsing), so a failure here would only be a
	// mismatched address family, which can't happen given the Is4() split.
	// v6 prefixes are dropped entirely when IPv6 is globally disabled
	// (general "ipv6" config, not dns.ipv6): the kernel won't pass v6
	// traffic to mihomo at all, so pbrcidr6 must stay empty to match.
	add := func(prefix netip.Prefix) {
		if prefix.Addr().Is4() {
			_ = set4.AddIpCidr(prefix)
		} else if !resolver.DisableIPv6 {
			_ = set6.AddIpCidr(prefix)
		}
	}

	for _, rp := range tunnel.RuleProviders() {
		if ctx.Err() != nil {
			return
		}

		switch rp.Behavior() {
		case P.IPCIDR:
			cp, ok := rp.Strategy().(cidrProvider)
			if !ok || cp == nil {
				log.Warnln("[nftcidrset] provider %s: behavior=IPCIDR but Strategy() does not implement cidrProvider", rp.Name())
				continue
			}
			cp.Foreach(func(prefix netip.Prefix) bool {
				add(prefix)
				return ctx.Err() == nil
			})
		case P.Classical:
			rl, ok := rp.Strategy().(ruleLister)
			if !ok || rl == nil {
				log.Warnln("[nftcidrset] provider %s: behavior=Classical but Strategy() does not implement ruleLister", rp.Name())
				continue
			}
			for _, rule := range rl.Rules() {
				if rule.RuleType() != C.IPCIDR {
					continue
				}
				prefix, err := netip.ParsePrefix(rule.Payload())
				if err != nil {
					log.Warnln("[nftcidrset] provider %s: bad IP-CIDR payload %q: %s", rp.Name(), rule.Payload(), err.Error())
					continue
				}
				add(prefix)
			}
		}
	}

	if ctx.Err() != nil {
		return
	}

	// Merge collapses overlapping/duplicate CIDRs across providers into the
	// minimal set of disjoint ranges — required because nftables interval
	// sets reject inserting two elements with overlapping keys (EEXIST), and
	// two independent rule-providers/subscriptions have no reason to be
	// mutually disjoint.
	if err := set4.Merge(); err != nil {
		log.Errorln("[nftcidrset] merge v4: %s", err.Error())
		return
	}
	if err := set6.Merge(); err != nil {
		log.Errorln("[nftcidrset] merge v6: %s", err.Error())
		return
	}

	var v4, v6 []netip.Prefix
	set4.Foreach(func(prefix netip.Prefix) bool { v4 = append(v4, prefix); return true })
	set6.Foreach(func(prefix netip.Prefix) bool { v6 = append(v6, prefix); return true })

	sortPrefixes(v4)
	sortPrefixes(v6)

	hash := hashPrefixes(v4, v6)

	mu.Lock()
	changed := !hash.Equal(lastHash)
	mu.Unlock()
	if !changed {
		log.Infoln("[nftcidrset] pbrcidr4/pbrcidr6 content doesn't change")
		return
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	// Re-check after acquiring the write lock: a run that was superseded
	// while waiting must not clobber a newer run's already-written result.
	if ctx.Err() != nil {
		return
	}

	if err := replace(v4, v6); err != nil {
		log.Errorln("[nftcidrset] replace: %s", err.Error())
		return
	}
	log.Infoln("[nftcidrset] replaced pbrcidr4/pbrcidr6: v4=%d v6=%d hash=%s", len(v4), len(v6), hash.String())

	mu.Lock()
	lastHash = hash
	mu.Unlock()
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].String() < prefixes[j].String()
	})
}

func hashPrefixes(v4, v6 []netip.Prefix) utils.HashType {
	buf := make([]byte, 0, (len(v4)+len(v6))*20)
	for _, p := range v4 {
		buf = append(buf, p.String()...)
		buf = append(buf, '\n')
	}
	buf = append(buf, '|')
	for _, p := range v6 {
		buf = append(buf, p.String()...)
		buf = append(buf, '\n')
	}
	return utils.MakeHash(buf)
}

func replace(v4, v6 []netip.Prefix) error {
	conn := &nftables.Conn{}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	set4 := &nftables.Set{Table: table, Name: cidrSetName4, Interval: true}

	conn.FlushSet(set4)
	for _, batch := range batchElements(v4) {
		conn.SetAddElements(set4, batch)
	}

	// Skip pbrcidr6 entirely when IPv6 is globally disabled (general "ipv6"
	// config, not dns.ipv6): v6 is never populated in this case (see add()
	// in run()), and touching a set that an external init script may not
	// have created for this mode risks aborting the whole transaction.
	if !resolver.DisableIPv6 {
		set6 := &nftables.Set{Table: table, Name: cidrSetName6, Interval: true}
		conn.FlushSet(set6)
		for _, batch := range batchElements(v6) {
			conn.SetAddElements(set6, batch)
		}
	}

	return conn.Flush()
}

func batchElements(prefixes []netip.Prefix) [][]nftables.SetElement {
	if len(prefixes) == 0 {
		return nil
	}
	batches := make([][]nftables.SetElement, 0, (len(prefixes)+cidrBatchSize-1)/cidrBatchSize)
	for start := 0; start < len(prefixes); start += cidrBatchSize {
		end := start + cidrBatchSize
		if end > len(prefixes) {
			end = len(prefixes)
		}
		batch := make([]nftables.SetElement, 0, end-start)
		for _, prefix := range prefixes[start:end] {
			batch = append(batch, elementsForPrefix(prefix)...)
		}
		batches = append(batches, batch)
	}
	return batches
}

// elementsForPrefix converts a CIDR into a single nftables interval element
// (requires the set to have `flags interval`): [network, broadcast+1).
// The upper bound is exclusive, so it's the address right after the last
// one in the prefix — computed as a big-endian byte increment, which
// overflows to all-zero on the very top of the address space (e.g.
// 255.255.255.255/32 or ::/0); nftables treats that as "no upper bound".
func elementsForPrefix(prefix netip.Prefix) []nftables.SetElement {
	network := prefix.Masked().Addr()
	broadcast := lastAddr(prefix)

	hi := broadcast.AsSlice()
	overflow := incrementBytes(hi)

	elems := []nftables.SetElement{
		{Key: network.AsSlice()},
	}
	if !overflow {
		elems = append(elems, nftables.SetElement{Key: hi, IntervalEnd: true})
	}
	return elems
}

// lastAddr returns the last address covered by prefix (the "broadcast"
// address for IPv4, the last address of the range for IPv6).
func lastAddr(prefix netip.Prefix) netip.Addr {
	network := prefix.Masked().Addr()
	b := network.AsSlice()
	hostBits := len(b)*8 - prefix.Bits()
	for i := len(b) - 1; hostBits > 0; i-- {
		if hostBits >= 8 {
			b[i] = 0xff
			hostBits -= 8
		} else {
			b[i] |= 0xff >> (8 - hostBits)
			hostBits = 0
		}
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

// incrementBytes adds 1 to a big-endian byte slice in place. Returns true
// if the addition overflowed (all bytes were 0xff).
func incrementBytes(b []byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return false
		}
	}
	return true
}
