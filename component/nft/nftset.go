// This file (nftset.go) adds resolved IPs to a pair of pre-existing nftables
// sets so that downstream PBR (policy-based routing) rules can use them.
//
// The sets must be created externally (e.g. by OpenWrt init scripts):
//
//	nft add table inet clash
//	nft 'add set inet clash pbr  { type ipv4_addr; flags timeout, dynamic; timeout 24h; }'
//	nft 'add set inet clash pbr6 { type ipv6_addr; flags timeout, dynamic; timeout 24h; }'
//
// Submit is called from the DNS resolver's own answer-handling goroutine
// when a request is flagged for PBR routing — it runs synchronously (after
// the DNS answer has already been returned to the client) and blocks only
// on submitMu, never on a queue. See nftcidrset.go for the companion
// rule-provider-CIDR mirror in this same package.
package nft

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/nftables"
	D "github.com/miekg/dns"
)

const (
	tableName = "clash"
	setName4  = "pbr"
	setName6  = "pbr6"
)

// submitMu serializes nftables transactions issued by Submit: concurrent DNS
// answers resolve on their own goroutines, and nftables.Conn transactions
// from two concurrent runs can interleave in the kernel, so only one Submit
// may be flushing at a time. Each call still gets its own transaction — the
// wait is just for the real netlink round-trip ahead of it, not a fixed
// batching delay.
var submitMu sync.Mutex

// Submit extracts global-unicast A/AAAA records from msg and adds them to
// the corresponding nftables set in a single transaction. AAAA records are
// dropped entirely when IPv6 is globally disabled — the kernel won't pass
// v6 traffic to mihomo anyway, so there's no point tracking resolved v6
// addresses.
//
// Returns an error if the nftables transaction fails for either address
// family. A partial failure (e.g. v4 succeeds, v6 fails) is still reported
// as an error: the caller can only accept or reject the whole DNS answer,
// and the resulting set state is not fully known either way.
func Submit(msg *D.Msg) error {
	if msg == nil {
		return nil
	}

	var pending4, pending6 []nftables.SetElement
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
		if ip.Is4() {
			pending4 = append(pending4, nftables.SetElement{Key: ip.AsSlice()})
		} else {
			pending6 = append(pending6, nftables.SetElement{Key: ip.AsSlice()})
		}
	}
	if len(pending4) == 0 && len(pending6) == 0 {
		return nil
	}

	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	set4 := &nftables.Set{Table: table, Name: setName4}
	set6 := &nftables.Set{Table: table, Name: setName6}

	// refresh adds, deletes, then re-adds each element in a single netlink
	// transaction. nftables cannot replace a set element's timeout in place
	// (no NLM_F_REPLACE for set elems), and deleting a non-existent element
	// fails with ENOENT. The leading add guarantees the element exists so the
	// delete always succeeds, and the trailing add re-creates it with a fresh
	// timeout — all atomic, so the IP is never absent from the set mid-flush.
	refresh := func(conn *nftables.Conn, set *nftables.Set, pending []nftables.SetElement) error {
		if len(pending) == 0 {
			return nil
		}
		if err := conn.SetAddElements(set, pending); err != nil {
			log.Errorln("[nftset] add(pre) inet/%s/%s: %s", tableName, set.Name, err.Error())
			return fmt.Errorf("add(pre) inet/%s/%s: %w", tableName, set.Name, err)
		}
		if err := conn.SetDeleteElements(set, pending); err != nil {
			log.Errorln("[nftset] delete inet/%s/%s: %s", tableName, set.Name, err.Error())
			return fmt.Errorf("delete inet/%s/%s: %w", tableName, set.Name, err)
		}
		if err := conn.SetAddElements(set, pending); err != nil {
			log.Errorln("[nftset] add inet/%s/%s: %s", tableName, set.Name, err.Error())
			return fmt.Errorf("add inet/%s/%s: %w", tableName, set.Name, err)
		}
		return nil
	}

	submitMu.Lock()
	defer submitMu.Unlock()

	conn := &nftables.Conn{}
	// A failure on either family is reported as a whole: the resulting set
	// state (which elements actually landed) is not fully known either way,
	// so there is no meaningful "partial success" to report to the caller.
	err4 := refresh(conn, set4, pending4)
	err6 := refresh(conn, set6, pending6)
	if err := conn.Flush(); err != nil {
		log.Errorln("[nftset] flush: %s", err.Error())
		return fmt.Errorf("flush: %w", err)
	}
	if err4 != nil {
		return err4
	}
	return err6
}
