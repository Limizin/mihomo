package context

import (
	"context"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

const (
	DNSTypeHost   = "host"
	DNSTypeFakeIP = "fakeip"
	DNSTypeRaw    = "raw"
)

type DNSContext struct {
	context.Context

	id     uuid.UUID
	tp     string
	nftAdd bool
}

func NewDNSContext(ctx context.Context) *DNSContext {
	return &DNSContext{
		Context: ctx,

		id: utils.NewUUIDV4(),
	}
}

// ID implement C.PlainContext ID
func (c *DNSContext) ID() uuid.UUID {
	return c.id
}

// SetType set type of response
func (c *DNSContext) SetType(tp string) {
	c.tp = tp
}

// Type return type of response
func (c *DNSContext) Type() string {
	return c.tp
}

// SetNftAdd marks this DNS request so that its resolved IPs should be added to the nftables PBR set.
func (c *DNSContext) SetNftAdd(v bool) {
	c.nftAdd = v
}

// NftAdd returns whether resolved IPs should be added to the nftables PBR set.
func (c *DNSContext) NftAdd() bool {
	return c.nftAdd
}
