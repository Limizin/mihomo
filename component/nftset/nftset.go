// Package nftset adds resolved IPs to a pair of pre-existing nftables sets so
// that downstream PBR (policy-based routing) rules can use them.
//
// The sets must be created externally (e.g. by OpenWrt init scripts):
//
//	nft add table inet clash
//	nft 'add set inet clash pbr  { type ipv4_addr; flags timeout, dynamic; timeout 24h; }'
//	nft 'add set inet clash pbr6 { type ipv6_addr; flags timeout, dynamic; timeout 24h; }'
//
// Submit is a non-blocking, fire-and-forget hook called from the DNS resolver
// when a request is flagged for PBR routing.
package nftset

import (
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/nftables"
	D "github.com/miekg/dns"
)

const (
	tableName = "clash"
	setName4  = "pbr"
	setName6  = "pbr6"

	channelSize = 1024
	dedupSize   = 10000
	dedupAge    = 5 * 60 // seconds

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
// channel is full.
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
	dedup := lru.New(
		lru.WithSize[netip.Addr, struct{}](dedupSize),
		lru.WithAge[netip.Addr, struct{}](dedupAge),
	)

	conn := &nftables.Conn{}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	set4 := &nftables.Set{Table: table, Name: setName4}
	set6 := &nftables.Set{Table: table, Name: setName6}

	pending4 := make([]nftables.SetElement, 0, batchSize)
	pending6 := make([]nftables.SetElement, 0, batchSize)
	timer := time.NewTimer(batchTimeout)
	timer.Stop()
	timerActive := false

	flush := func() {
		if len(pending4) > 0 {
			if err := conn.SetAddElements(set4, pending4); err != nil {
				log.Warnln("[nftset] SetAddElements %s/%s/%s: %s", "inet", tableName, setName4, err.Error())
			}
			pending4 = pending4[:0]
		}
		if len(pending6) > 0 {
			if err := conn.SetAddElements(set6, pending6); err != nil {
				log.Warnln("[nftset] SetAddElements %s/%s/%s: %s", "inet", tableName, setName6, err.Error())
			}
			pending6 = pending6[:0]
		}
		if err := conn.Flush(); err != nil {
			log.Warnln("[nftset] Flush: %s", err.Error())
		}
	}

	for {
		select {
		case e := <-ch:
			if _, ok := dedup.Get(e.ip); ok {
				continue
			}
			dedup.Set(e.ip, struct{}{})

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
