// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"
	"log"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// defaultDupAddrDetectTransmits is the default number of NDP Neighbor
	// Solicitation messages to send when doing Duplicate Address Detection
	// for a tentative address.
	//
	// Default = 1 (from RFC 4862 section 5.1)
	defaultDupAddrDetectTransmits = 1

	// defaultRetransmitTimer is the default amount of time to wait between
	// sending NDP Neighbor solicitation messages.
	//
	// Default = 1s (from RFC 4861 section 10).
	defaultRetransmitTimer = time.Second

	// defaultHandleRAs is the default configuration for whether or not to
	// handle incoming Router Advertisements as a host.
	//
	// Default = true.
	defaultHandleRAs = true

	// defaultDiscoverDefaultRouters is the default configuration for
	// whether or not to discover default routers from incoming Router
	// Advertisements as a host.
	//
	// Default = true.
	defaultDiscoverDefaultRouters = true

	// defaultAutoUpdateRoutingTable is the default configuration for
	// whether or not the stack will update the routing table with default
	// routes to newly discovered default routers.
	defaultAutoUpdateRoutingTable = true

	// minimumRetransmitTimer is the minimum amount of time to wait between
	// sending NDP Neighbor solicitation messages. Note, RFC 4861 does
	// not impose a minimum Retransmit Timer, but we do here to make sure
	// the messages are not sent all at once. We also come to this value
	// because in the RetransmitTimer field of a Router Advertisement, a
	// value of 0 means unspecified, so the smallest valid value is 1.
	// Note, the unit of the RetransmitTimer field in the Router
	// Advertisement is milliseconds.
	//
	// Min = 1ms.
	minimumRetransmitTimer = time.Millisecond

	// MaxDiscoveredDefaultRouters is the maximum number of discovered
	// default routers. The stack should stop discovering new routers after
	// discovering MaxDiscoveredDefaultRouters routers.
	//
	// This value MUST be at minimum 2 as per RFC 4861 section 6.3.4, and
	// SHOULD be more.
	//
	// Max = 10.
	MaxDiscoveredDefaultRouters = 10
)

// NDPConfigurations is the NDP configurations for the netstack.
type NDPConfigurations struct {
	// The number of Neighbor Solicitation messages to send when doing
	// Duplicate Address Detection for a tentative address.
	//
	// Note, a value of zero effectively disables DAD.
	DupAddrDetectTransmits uint8

	// The amount of time to wait between sending Neighbor solicitation
	// messages.
	//
	// Must be greater than 0.5s.
	RetransmitTimer time.Duration

	// HandleRAs determines whether or not Router Advertisements will be
	// processed.
	HandleRAs bool

	// DiscoverDefaultRouters determines whether or not default routers will
	// be discovered from Router Advertisements. This configuration is
	// ignored if HandleRAs is false.
	DiscoverDefaultRouters bool

	// AutoUpdateRoutingTable determines whether or not the stack will
	// update the routing table's default routes with discovered
	// default routers.
	AutoUpdateRoutingTable bool
}

// DefaultNDPConfigurations returns an NDPConfigurations populated with
// default values.
func DefaultNDPConfigurations() NDPConfigurations {
	return NDPConfigurations{
		DupAddrDetectTransmits: defaultDupAddrDetectTransmits,
		RetransmitTimer:        defaultRetransmitTimer,
		HandleRAs:              defaultHandleRAs,
		DiscoverDefaultRouters: defaultDiscoverDefaultRouters,
		AutoUpdateRoutingTable: defaultAutoUpdateRoutingTable,
	}
}

// validateNDPConfiguration modifies an NDPConfigurations with valid values.
// If invalid values are present in c, the corresponding default values will
// be used instead.
//
// If RetransmitTimer is less than minimumRetransmitTimer, then a value of
// defaultRetransmitTimer will be used.
func validateNDPConfiguration(c *NDPConfigurations) {
	if c.RetransmitTimer < minimumRetransmitTimer {
		c.RetransmitTimer = defaultRetransmitTimer
	}
}

// ndpState is the per-interface NDP state.
type ndpState struct {
	// configs is the per-interface NDP configurations.
	configs NDPConfigurations

	// The DAD ticker to send the next NS message, or resolve the address.
	dad map[tcpip.Address]dadTicker

	// The default routers discovered through Router Advertisements.
	defaultRouters map[tcpip.Address]defaultRouterState
}

// makeNDPState returns an ndpState with the provided per-interface NDP
// configurations.
//
// Note, c must be valid.
func makeNDPState(c NDPConfigurations) ndpState {
	return ndpState{
		configs:        c,
		dad:            make(map[tcpip.Address]dadTicker),
		defaultRouters: make(map[tcpip.Address]defaultRouterState),
	}
}

// dadTicker holds the Duplicate Address Detection ticker and channel to signal
// to the DAD goroutine that DAD should stop.
type dadTicker struct {
	// The DAD ticker to send the next NS message, or resolve the address.
	ticker *time.Ticker

	// The channel the DAD goroutine will expect to receive from to end.
	tickerDone chan struct{}
}

// defaultRouterState holds data associated with a default router discovered by
// a router advertisement when the NDP configurations was configured to do so.
type defaultRouterState struct {
	invalidationTimer *time.Timer
}

// startDuplicateAddressDetection performs Duplicate Address Detection.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to (n) MUST be locked.
func (ndp *ndpState) startDuplicateAddressDetection(n *NIC, addr tcpip.Address, ref *referencedNetworkEndpoint) *tcpip.Error {
	// addr must be a valid unicast IPv6 address.
	if !header.IsV6UnicastAddress(addr) {
		return tcpip.ErrAddressFamilyNotSupported
	}

	// addr must currently be tentative.
	if ref.kind != permanentTentative {
		// Should never happen because we should only ever call this
		// function for newly created tentative addresses. When we
		// add new unicast IPv6 addresses, we set it to tentative and
		// start the DAD process on it (as per RFC 4862 section 5.4).
		// See NIC.addAddressLocked for more details.
		panic(fmt.Sprintf("ndpdad: addr %s is not tentative on NIC(%d)", addr, n.ID()))
	}

	// Should not attempt to perform DAD on an address that is currently in
	// the DAD process.
	if _, ok := ndp.dad[addr]; ok {
		// Should never happen because we should only ever call this
		// function for newly created addresses. If we attemped to
		// "add" an address that already existed, we would returned an
		// error since we attempted to add a duplicate address, or its
		// reference count would have been increased without doing the
		// work that would have been done for an address that was brand
		// new. See NIC.addPermanentAddressLocked.
		panic(fmt.Sprintf("ndpdad: already performing DAD for addr %s on NIC(%d)", addr, n.ID()))
	}

	dupAddrDetectTransmits := ndp.configs.DupAddrDetectTransmits

	// DAD is disabled. Resolve immediately.
	if dupAddrDetectTransmits == 0 {
		// Assign immediately.
		ref.setKind(permanent)
		return nil
	}

	// Start the DAD goroutine.
	ticker := time.NewTicker(ndp.configs.RetransmitTimer)
	tickerDone := make(chan struct{}, 1)
	ndp.dad[addr] = dadTicker{
		ticker:     ticker,
		tickerDone: tickerDone,
	}

	go func() {
		// Do the first iteration immediately.
		if ndp.doDuplicateAddressDetectionIteration(tickerDone, n, addr, dupAddrDetectTransmits) {
			return
		}

		// We subtract 1 from dupAddrDetectTransmits since we already
		// did an iteration.
		remaining := dupAddrDetectTransmits - 1
		for {

			select {
			case <-tickerDone:
				return
			case <-ticker.C:
				if ndp.doDuplicateAddressDetectionIteration(tickerDone, n, addr, remaining) {
					return
				}
				remaining--
			}
		}
	}()

	return nil
}

// doDuplicateAddressDetectionIteration is called on every iteration of the
// timer. It handles the job of locking n, actually doing the DAD work
// and ending DAD when appropriate.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// Returns true if DAD has completed (resolved or failed).
func (ndp *ndpState) doDuplicateAddressDetectionIteration(tickerDone chan struct{}, n *NIC, addr tcpip.Address, remaining uint8) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Now that we have the lock, make sure that we are actually supposed to
	// do DAD still. We need to check this AFTER obtaining the NIC lock to
	// prevent the following race.
	//
	// Let C1 and C2 represent two concurrently running oroutines. C1 will
	// represent the DAD goroutine, and C2 will be a couroutine that handles
	// an incoming NDP packet that informs the node that the address (addr)
	// C1 is doing DAD on is detected to be a duplicate on a link. Assume C1
	// and C2 are running on different threads. Also assume C1 is currently
	// in the DAD goroutine loop.
	//
	// C1: ticker.C fires before tickerDone; (only) enter this function.
	// C2: Learn from the network that addr is a duplicate.
	// C2: Inform the NIC that the addr is a duplicate
	//     (nic.dupTentativeAddrDetected).
	// C2: Obtain NIC lock.
	// C2: NIC removes address (which ends up calling
	//     ndp.stopDuplicateAddressDetection for addr.
	// C2: NIC stops the DAD ticker and signals C1 (via the tickerDone
	//     channel) that it should end.
	// C2: Remove DAD state associated with NIC.
	// C2: Release NIC lock.
	// C1: Continues execution of
	//     ndp.doDuplicateAddressDetectionIteration:
	// C1: Obtain NIC lock & attempt to get DAD state for addr but fail and
	//     panic.
	//
	// We can see that we attempted to continue the DAD process after it has
	// been stopped.
	//
	// To resolve this, we check the tickerDone channel for any signal to
	// end before doing the actual DAD work. We early-return if it fired, or
	// proceed as normal otherwise.
	//
	// Note, another idea was to add a lock BEFORE waiting on the tickerDone
	// and ticker.C channels, but that would prevent updates to the NIC
	// until the next ticker tick. Note, if we obtain the lock before
	// DAD is stopped, then tickerDone will never fire as
	// nic.dupTentativeAddrDetected (which needs to obtain the lock before
	// stopping DAD) will not be able to proceed. So the only way the lock
	// will be released after obtaining it (in this specific scenario) is
	// after the ticker ticks. This could hang a NIC for a while if the
	// retransmit timer was relatively large (it could be up to 255s).
	//
	// The simpler (and more performant) solution is to just wait on the
	// channels without obtaining the lock and then if the ticker ticks,
	// check if DAD has been stopped after obtaining the lock, safe from
	// races.
	//
	// We could have also just early-returned if the DAD was not found for
	// addr, but that could also imply some other bug (did we delete the
	// addr but forget to stop DAD?).
	select {
	case <-tickerDone:
		return true
	default:
		// tickerDone still has not been fired so we are safe to
		// proceed.
	}

	if done, err := ndp.doDuplicateAddressDetection(n, addr, remaining); err != nil || done {
		if err != nil {
			log.Printf("ndpdad: Error occured during DAD iteration for addr (%s) on NIC(%d); err = %s", addr, n.ID(), err)
		}

		ndp.stopDuplicateAddressDetection(addr)
		return true
	}

	return false
}

// doDuplicateAddressDetection is called on every iteration of the timer, and
// when DAD starts.
//
// This function must only be called by IPv6 addresses that are currently
// tentative.
//
// The NIC that ndp belongs to (n) MUST be locked.
//
// Returns true if DAD has completed (resolved or failed).
func (ndp *ndpState) doDuplicateAddressDetection(n *NIC, addr tcpip.Address, remaining uint8) (bool, *tcpip.Error) {
	ref, ok := n.endpoints[NetworkEndpointID{addr}]
	if !ok {
		// This should never happen.
		// We should have an endpoint for addr since we are
		// still performing DAD on it. If the endpoint does not
		// exist, but we are doing DAD on it, then we started
		// DAD at some point, but forgot to stop it when the
		// endpoint was deleted.
		panic(fmt.Sprintf("ndpdad: unrecognized addr %s for NIC(%d)", addr, n.ID()))
	}

	if ref.kind != permanentTentative {
		// The endpoint should still be marked as tentative
		// since we are still performing DAD on it.
		panic(fmt.Sprintf("ndpdad: addr %s is not tentative on NIC(%d)", addr, n.ID()))
	}

	if remaining == 0 {
		// DAD has resolved.
		ref.setKind(permanent)
		return true, nil
	}

	// Send a new NS.
	snmc := header.SolicitedNodeAddr(addr)
	snmcRef, ok := n.endpoints[NetworkEndpointID{snmc}]
	if !ok {
		// This should never happen as if we have the
		// address, we should have the solicited-node
		// address.
		panic(fmt.Sprintf("ndpdad: NIC(%d) is not in the solicited-node multicast group (%s) but it has addr %s", n.ID(), snmc, addr))
	}

	// Use the unspecified address as the source address when
	// performing DAD.
	r := makeRoute(header.IPv6ProtocolNumber, header.IPv6Any, snmc, n.linkEP.LinkAddress(), snmcRef, false, false)

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()) + header.ICMPv6NeighborSolicitMinimumSize)
	pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
	pkt.SetType(header.ICMPv6NeighborSolicit)
	ns := header.NDPNeighborSolicit(pkt.NDPPayload())
	ns.SetTargetAddress(addr)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, r.LocalAddress, r.RemoteAddress, buffer.VectorisedView{}))

	sent := r.Stats().ICMP.V6PacketsSent
	if err := r.WritePacket(nil, hdr, buffer.VectorisedView{}, header.ICMPv6ProtocolNumber, r.DefaultTTL()); err != nil {
		sent.Dropped.Increment()
		return false, err
	}
	sent.NeighborSolicit.Increment()

	return false, nil
}

// stopDuplicateAddressDetection ends a running Duplicate Address Detection
// process. Note, this may leave the DAD process for a tentative address in
// such a state forever, unless some other external event resolves the DAD
// process (receiving an NA from the true owner of addr, or an NS for addr
// (implying another node is attempting to use addr)). It is up to the caller
// of this function to handle such a scenario. Normally, addr will be removed
// from n right after this function returns or the address successfully
// resolved.
//
// The NIC that ndp belongs to MUST be locked.
func (ndp *ndpState) stopDuplicateAddressDetection(addr tcpip.Address) {
	dad, ok := ndp.dad[addr]
	if !ok {
		// Not currently performing DAD on addr, just return.
		return
	}

	// If we have a ticker set, stop it.
	if dad.ticker != nil {
		dad.ticker.Stop()
		dad.tickerDone <- struct{}{}
		dad.tickerDone = nil
		dad.ticker = nil
	}

	// Delete the dadTicker for addr.
	delete(ndp.dad, addr)

	return
}

// setConfigs sets the NDP configurations for ndp.
func (ndp *ndpState) setConfigs(c NDPConfigurations) {
	// Make sure invalid values are fixed.
	validateNDPConfiguration(&c)

	ndp.configs = c
}

// handleRA handles a Router Advertisement message that arrived on the NIC (n)
// this ndp is for. Does nothing if n is configured to not handle RAs or if
// n is a routing interface.
//
// n and n.stack MUST be locked.
func (ndp *ndpState) handleRA(n *NIC, ip tcpip.Address, ra header.NDPRouterAdvert) {
	// Is n configured to handle RAs at all?
	//
	// Currently, the stack does not determine router interface status on a
	// per-interface basis; it is a stack-wide configuration, so we check
	// stack's forwarding flag to determine if n is a routing interface.
	if !ndp.configs.HandleRAs || n.stack.forwarding {
		return
	}

	// Is n configured to discover default routers?
	if ndp.configs.DiscoverDefaultRouters {
		// TODO(b/140882146): Do Router Discovery.
		rtr, ok := ndp.defaultRouters[ip]
		rl := ra.RouterLifetime()
		if !ok && rl != 0 {
			// This is a new default router we are discovering.
			//
			// Only remember it if we currently know about less than
			// MaxDiscoveredDefaultRouters routers.
			if len(ndp.defaultRouters) < MaxDiscoveredDefaultRouters {
				ndp.rememberDefaultRouter(n, ip, rl)
			}
		} else if ok && rl != 0 {
			// This is an already discovered default router. Update
			// the invalidation timer.
			timer := rtr.invalidationTimer

			// We should ALWAYS have an invalidation timer for a
			// discovered router.
			if timer == nil {
				panic("ndphandlera: RA invalidation timer should not be nil")
			}

			if timer.Stop() {
				// The timer was successfully stopped so we know
				// it has not yet fired. Reset the invalidation
				// timer to expire after the Router Lifetime,
				// rl.
				timer.Reset(rl)
			} else {
				// The timer fired after taking the n.mu Lock.
				// Invalidate the router here immediately. If we
				// did nothing, the timer would have invalidated
				// it right after we release the lock, but let's
				// be explicit and handle an unknown router in
				// the invalidation timer callback.
				ndp.invalidateDefaultRouter(n, ip)
			}
		} else if ok && rl == 0 {
			// We know about the router but it is no longer to be
			// used as a default router so invalidate it.
			ndp.invalidateDefaultRouter(n, ip)
		}
	}

	// TODO(b/140948104): Do Prefix Discovery.
	// TODO(b/141556115): Do Parameter Discovery.
}

// invalidateDefaultRouter invalidates a discovered default router.
//
// n and n.stack MUST be locked.
func (ndp *ndpState) invalidateDefaultRouter(n *NIC, ip tcpip.Address) {
	// TODO(b/141569273): Inform the integrator when we invalidate a
	//                    discovered default router.

	rtr, ok := ndp.defaultRouters[ip]

	// Is the router still discovered?
	if !ok {
		// ...Nope, do nothing further.
		return
	}

	// If n is configured to auto-update the routing table, then remove
	// the default route, if it exists.
	if ndp.configs.AutoUpdateRoutingTable {
		rt := make([]tcpip.Route, 0)

		exclude := tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			Gateway:     ip,
			NIC:         n.ID(),
		}

		for _, r := range n.stack.routeTable {
			if r != exclude {
				rt = append(rt, r)
			}
		}

		n.stack.routeTable = rt
	}

	rtr.invalidationTimer.Stop()
	rtr.invalidationTimer = nil

	delete(ndp.defaultRouters, ip)
}

// rememberDefaultRouter remembers a newly discovered default router with IPv6
// address ip with lifetime rl.
//
// The router identified by ip MUST NOT already be known by n.
//
// n and n.stack MUST be locked.
func (ndp *ndpState) rememberDefaultRouter(n *NIC, ip tcpip.Address, rl time.Duration) {
	// TODO(b/141569273): Inform the integrator when we remember a
	//                    discovered default router.

	ndp.defaultRouters[ip] = defaultRouterState{
		invalidationTimer: time.AfterFunc(rl, func() {
			n.stack.mu.Lock()
			defer n.stack.mu.Unlock()
			n.mu.Lock()
			defer n.mu.Unlock()
			ndp.invalidateDefaultRouter(n, ip)
		}),
	}

	// If n is configured to auto-update the routing table, then add
	// the default route.
	if ndp.configs.AutoUpdateRoutingTable {
		rt := append([]tcpip.Route(nil), n.stack.routeTable...)

		// Add a default route that sends packets out n and uses the
		// discovered router as a next hop node.
		rt = append(rt, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			Gateway:     ip,
			NIC:         n.ID(),
		})

		n.stack.routeTable = rt
	}
}
