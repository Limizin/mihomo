// This file (nftset.go) adds resolved IPs to a pair of pre-existing nftables
// sets so that downstream PBR (policy-based routing) rules can use them.
//
// The sets must be created externally (e.g. by OpenWrt init scripts):
//
//	nft add table inet clash
//	nft 'add set inet clash pbr  { type ipv4_addr; flags timeout, dynamic; timeout 24h; }'
//	nft 'add set inet clash pbr6 { type ipv6_addr; flags timeout, dynamic; timeout 24h; }'
//
// Submit is a non-blocking, fire-and-forget hook called from the DNS resolver
// when a request is flagged for PBR routing. See nftcidrset.go for the
// companion rule-provider-CIDR mirror in this same package.
package nft

import (
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/nftables"
	D "github.com/miekg/dns"
)

const (
	tableName = "clash"
	setName4  = "pbr"
	setName6  = "pbr6"

	channelSize = 1024

	batchSize    = 128
	batchTimeout = 100 * time.Millisecond
)

type entry struct {
	ip netip.Addr
}

var (
	ch       chan entry
	initOnce sync.Once
)

func ensureStarted() {
	initOnce.Do(func() {
		ch = make(chan entry, channelSize)
		go worker()
	})
}

// Submit extracts global-unicast A/AAAA records from msg and asynchronously
// adds them to the corresponding nftables set. Drops silently if the worker
// channel is full. AAAA records are dropped entirely when IPv6 is globally
// disabled — the kernel won't pass v6 traffic to mihomo anyway, so there's
// no point tracking resolved v6 addresses.
func Submit(msg *D.Msg) {
	if msg == nil {
		return
	}
	ensureStarted()
	for _, ans := range msg.Answer {
		var ip netip.Addr
		switch a := ans.(type) {
		case *D.A:
			ip, _ = netip.AddrFromSlice(a.A)
		case *D.AAAA:
			if resolver.DisableIPv6 {
				continue
			}
			ip, _ = netip.AddrFromSlice(a.AAAA)
		default:
			continue
		}
		if !ip.IsValid() || !ip.IsGlobalUnicast() {
			continue
		}
		ip = ip.Unmap()
		select {
		case ch <- entry{ip: ip}:
		default:
			// channel full — drop silently to keep DNS path non-blocking
		}
	}
}

func worker() {
	conn := &nftables.Conn{}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	set4 := &nftables.Set{Table: table, Name: setName4}
	set6 := &nftables.Set{Table: table, Name: setName6}

	pending4 := make([]nftables.SetElement, 0, batchSize)
	pending6 := make([]nftables.SetElement, 0, batchSize)
	timer := time.NewTimer(batchTimeout)
	timer.Stop()
	timerActive := false

	// refresh adds, deletes, then re-adds each element in a single netlink
	// transaction. nftables cannot replace a set element's timeout in place
	// (no NLM_F_REPLACE for set elems), and deleting a non-existent element
	// fails with ENOENT. The leading add guarantees the element exists so the
	// delete always succeeds, and the trailing add re-creates it with a fresh
	// timeout — all atomic, so the IP is never absent from the set mid-flush.
	refresh := func(set *nftables.Set, pending []nftables.SetElement) {
		if len(pending) == 0 {
			return
		}
		if err := conn.SetAddElements(set, pending); err != nil {
			log.Warnln("[nftset] add(pre) inet/%s/%s: %s", tableName, set.Name, err.Error())
			return
		}
		if err := conn.SetDeleteElements(set, pending); err != nil {
			log.Warnln("[nftset] delete inet/%s/%s: %s", tableName, set.Name, err.Error())
			return
		}
		if err := conn.SetAddElements(set, pending); err != nil {
			log.Warnln("[nftset] add inet/%s/%s: %s", tableName, set.Name, err.Error())
			return
		}
	}

	flush := func() {
		refresh(set4, pending4)
		refresh(set6, pending6)
		pending4 = pending4[:0]
		pending6 = pending6[:0]
		if err := conn.Flush(); err != nil {
			log.Warnln("[nftset] flush: %s", err.Error())
		}
	}

	for {
		select {
		case e := <-ch:
			if e.ip.Is4() {
				pending4 = append(pending4, nftables.SetElement{Key: e.ip.AsSlice()})
			} else {
				pending6 = append(pending6, nftables.SetElement{Key: e.ip.AsSlice()})
			}

			if len(pending4)+len(pending6) >= batchSize {
				if timerActive {
					if !timer.Stop() {
						<-timer.C
					}
					timerActive = false
				}
				flush()
			} else if !timerActive {
				timer.Reset(batchTimeout)
				timerActive = true
			}
		case <-timer.C:
			timerActive = false
			flush()
		}
	}
}
