package vxlan

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/TrilliumIT/iputil"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// HostInterface represents the host's connection to the vxlan
// It must be made up of both a "vxlan" interface which participates in the cluster's vxlan
// and a "macvlan" slave of the vxlan interface which acts as the hosts connection to that vxlan
// the hosts address gets isntalled on the macvlan
type HostInterface struct {
	VxlanParams *Vxlan
	vxLink      *netlink.Vxlan
	vxName      string
	mvLink      *netlink.Macvlan
	mvName      string
}

func newHostInterfaceShell(vxlan *Vxlan) *HostInterface {
	vxName := "vx_" + vxlan.Name
	mvName := "mv_" + vxlan.Name

	return &HostInterface{
		VxlanParams: vxlan,
		vxName:      vxName,
		mvName:      mvName,
	}
}

// GetOrCreateHostInterface creates required host interfaces if they don't exist, or gets them if they already do
func GetOrCreateHostInterface(vxlan *Vxlan) (*HostInterface, error) {
	hi, err := GetHostInterface(vxlan)
	if err == nil {
		log.Debugf("found existing host interface, returning")
		return hi, nil
	}

	return createHostInterface(vxlan)
}

func createHostInterface(vxlan *Vxlan) (*HostInterface, error) {
	hi := newHostInterfaceShell(vxlan)

	err := hi.createVxlanLink()
	if err != nil {
		log.Error("failed to create vxlan link")
		hi.DeleteLinks()
		return nil, err
	}

	hi.mvLink, err = hi.createMacvlanLink(hi.mvName)
	if err != nil {
		log.Error("failed to create host macvlan link")
		hi.DeleteLinks()
		return nil, err
	}

	err = hi.initializeMacvlanLink(hi.mvLink, hi.GetContainerGateway(), netns.None(), "")
	if err != nil {
		log.Error("failed to initialize host macvlan link")
		hi.DeleteLinks()
		return nil, err
	}

	err = hi.addBypassRoute()
	if err != nil {
		log.Error("failed validating/adding bypass route")
		hi.DeleteLinks()
		return nil, err
	}

	err = hi.addBypassRule()
	if err != nil {
		log.Error("failed validating/adding bypass rule")
		hi.DeleteLinks()
		return nil, err
	}

	return hi, nil
}

func GetHostInterface(vxlan *Vxlan) (*HostInterface, error) {
	var err error
	hi := newHostInterfaceShell(vxlan)

	var link netlink.Link
	link, err = netlink.LinkByName(hi.vxName)
	if err != nil {
		return nil, err
	}

	var ok bool
	hi.vxLink, ok = link.(*netlink.Vxlan)
	if !ok {
		hi.DeleteLinks()
		return nil, fmt.Errorf("link named %v is not a vxlan", hi.vxName)
	}

	link, err = netlink.LinkByName(hi.mvName)
	if err != nil {
		hi.DeleteLinks()
		return nil, err
	}

	hi.mvLink, ok = link.(*netlink.Macvlan)
	if !ok {
		hi.DeleteLinks()
		return nil, fmt.Errorf("link named %v is not a macvlan", hi.mvName)
	}

	address, err := netlink.ParseAddr(vxlan.Cidr)
	if err != nil {
		hi.DeleteLinks()
		return nil, err
	}

	if !linkHasAddress(hi.mvLink, address) {
		hi.DeleteLinks()
		return nil, fmt.Errorf("host macvlan link does not have expected address")
	}

	return hi, nil
}

func (hi *HostInterface) addBypassRule() error {
	log.Debugf("addBypassRule()")

	r, _ := hi.getBypassRule()
	if r != nil {
		log.Debugf("rule already exists")
		return nil
	}

	net := iputil.NetworkID(hi.GetContainerGateway())
	log.Debugf("add rule")
	rule := netlink.NewRule()
	rule.Src = net
	rule.Dst = net
	rule.Table = DefaultVxlanRouteTable

	err := netlink.RuleAdd(rule)
	if err != nil {
		log.WithError(err).Errorf("failed to add rule")
		return err
	}

	return nil
}

func (hi *HostInterface) getBypassRule() (*netlink.Rule, error) {
	log.Debugf("getBypassRule()")

	rules, err := netlink.RuleList(0)
	if err != nil {
		return nil, err
	}

	net := iputil.NetworkID(hi.GetContainerGateway())
	for _, r := range rules {
		if iputil.SubnetEqualSubnet(r.Src, net) && iputil.SubnetEqualSubnet(r.Dst, net) && r.Table == DefaultVxlanRouteTable {
			return &r, nil
		}
	}

	return nil, fmt.Errorf("bypass rule not found")
}

func (hi *HostInterface) delBypassRule() error {
	log.Debugf("delBypassRule()")

	r, err := hi.getBypassRule()
	if err != nil {
		return err
	}

	return netlink.RuleDel(r)
}

func (hi *HostInterface) addBypassRoute() error {
	log.Debugf("addBypassRoute()")
	net := iputil.NetworkID(hi.GetContainerGateway())

	r, _ := hi.getBypassRoute()
	if r != nil {
		log.Debugf("bypass route already exists, return")
		return nil
	}

	err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: hi.mvLink.Index,
		Dst:       net,
		Table:     DefaultVxlanRouteTable,
	})
	if err != nil {
		log.WithError(err).Errorf("failed to add bypass route")
		return err
	}

	return nil
}

func (hi *HostInterface) getBypassRoute() (*netlink.Route, error) {
	log.Debugf("getBypassRoute()")

	routes, err := netlink.RouteListFiltered(0, &netlink.Route{Table: DefaultVxlanRouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	net := iputil.NetworkID(hi.GetContainerGateway())
	for _, r := range routes {
		if iputil.SubnetEqualSubnet(r.Dst, net) && r.LinkIndex == hi.mvLink.Index {
			return &r, nil
		}
	}

	return nil, fmt.Errorf("bypass route not found")
}

func (hi *HostInterface) delBypassRoute() error {
	log.Debugf("delBypassRoute()")

	r, err := hi.getBypassRoute()
	if err != nil {
		return err
	}

	return netlink.RouteDel(r)
}

func (hi *HostInterface) createVxlanLink() error {
	nl := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: hi.vxName,
			//MTU:  hi.VxlanParams.MTU,
		},
		VxlanId: hi.VxlanParams.ID,
	}

	if shwa, ok := hi.GetOption("vxlanhardwareaddr"); ok {
		hwa, _ := net.ParseMAC(shwa)
		netlink.LinkSetHardwareAddr(nl, hwa)
	}
	if qlen, ok := hi.GetOption("vxlantxqlen"); ok {
		nl.LinkAttrs.TxQLen, _ = strconv.Atoi(qlen)
	}
	if vtep, ok := hi.GetOption("vtepdev"); ok {
		nl.VtepDevIndex, _ = linkIndexByName(vtep)
	}
	if srcaddr, ok := hi.GetOption("srcaddr"); ok {
		nl.SrcAddr = net.ParseIP(srcaddr)
	}
	if group, ok := hi.GetOption("group"); ok {
		nl.Group = net.ParseIP(group)
	}
	if ttl, ok := hi.GetOption("ttl"); ok {
		nl.TTL, _ = strconv.Atoi(ttl)
	}
	if tos, ok := hi.GetOption("tos"); ok {
		nl.TOS, _ = strconv.Atoi(tos)
	}
	if learning, ok := hi.GetOption("learning"); ok {
		nl.Learning, _ = strconv.ParseBool(learning)
	}
	if proxy, ok := hi.GetOption("proxy"); ok {
		nl.Proxy, _ = strconv.ParseBool(proxy)
	}
	if rsc, ok := hi.GetOption("rsc"); ok {
		nl.RSC, _ = strconv.ParseBool(rsc)
	}
	if l2miss, ok := hi.GetOption("l2miss"); ok {
		nl.L2miss, _ = strconv.ParseBool(l2miss)
	}
	if l3miss, ok := hi.GetOption("l3miss"); ok {
		nl.L3miss, _ = strconv.ParseBool(l3miss)
	}
	if noage, ok := hi.GetOption("noage"); ok {
		nl.NoAge, _ = strconv.ParseBool(noage)
	}
	if gbp, ok := hi.GetOption("gbp"); ok {
		nl.GBP, _ = strconv.ParseBool(gbp)
	}
	if age, ok := hi.GetOption("age"); ok {
		nl.Age, _ = strconv.Atoi(age)
	}
	if limit, ok := hi.GetOption("limit"); ok {
		nl.Limit, _ = strconv.Atoi(limit)
	}
	if port, ok := hi.GetOption("port"); ok {
		nl.Port, _ = strconv.Atoi(port)
	}
	if pl, ok := hi.GetOption("portlow"); ok {
		nl.PortLow, _ = strconv.Atoi(pl)
	}
	if ph, ok := hi.GetOption("porthigh"); ok {
		nl.PortLow, _ = strconv.Atoi(ph)
	}

	err := netlink.LinkAdd(nl)
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(nl)
	if err != nil {
		return err
	}

	hi.vxLink = nl

	return nil
}

func (hi *HostInterface) createMacvlanLink(name string) (*netlink.Macvlan, error) {
	nl := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: hi.vxLink.Index,
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}

	err := netlink.LinkAdd(nl)
	if err != nil {
		return nil, err
	}

	return nl, nil
}

func (hi *HostInterface) initializeMacvlanLink(nl *netlink.Macvlan, addr *net.IPNet, ns netns.NsHandle, ifname string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rootns, err := netns.Get()
	if err != nil {
		return err
	}
	defer rootns.Close()

	if ns.IsOpen() {
		err = netlink.LinkSetNsFd(nl, int(ns))
		if err != nil {
			return err
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		netns.Set(ns)
		defer netns.Set(rootns)

		err = netlink.LinkSetName(nl, ifname)
		if err != nil {
			return err
		}
	}

	err = netlink.LinkSetUp(nl)
	if err != nil {
		return err
	}

	err = netlink.AddrAdd(nl, &netlink.Addr{IPNet: addr})
	if err != nil {
		return err
	}

	if ns.IsOpen() {
		// add default route through host to routing table in container namespace
		_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
		err = netlink.RouteAdd(&netlink.Route{
			Dst: defaultDst,
			Gw:  hi.GetContainerGateway().IP,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

//GetOption gets the names vxlan option from the options map
func (hi *HostInterface) GetOption(opt string) (string, bool) {
	val, ok := hi.VxlanParams.Options[opt]
	return val, ok
}

//GetContainerGateway gets the gateway address and subnet from the vxlan config
func (hi *HostInterface) GetContainerGateway() *net.IPNet {
	ipnet, _ := netlink.ParseIPNet(hi.VxlanParams.Cidr)
	return ipnet
}

//AddContainerLink adds a new macvlan link to the vxlan link, adds an IP, and puts it in the requested namespace.
func (hi *HostInterface) AddContainerLink(namespace, ifname string, addr *net.IPNet) (int, error) {
	cns, err := netns.GetFromPath(namespace)
	defer func() {
		err := cns.Close()
		if err != nil {
			log.Debugf("error while closing container namespace: %v", err)
		}
	}()
	if err != nil {
		return -1, err
	}

	nsa := strings.Split(namespace, string(os.PathSeparator))
	if len(nsa) < 3 {
		return -1, fmt.Errorf("unexpected namespace path format")
	}

	//create interface with a temp name to prevent duplicates in the root namespace
	tempName := "cmvl_" + nsa[2]
	log.WithField("tempName", tempName).Debug("temporary interface name")
	cmvl, err := hi.createMacvlanLink(tempName)
	if err != nil {
		return -1, err
	}

	//set up, addr add, move to namespace
	err = hi.initializeMacvlanLink(cmvl, addr, cns, ifname)
	if err != nil {
		return -1, err
	}

	return cmvl.Index, nil
}

//DeleteContainerLink deletes the containers interface
func (hi *HostInterface) DeleteContainerLink(namespace, name string) error {
	rootns, err := netns.Get()
	if err != nil {
		return err
	}
	defer rootns.Close()

	cns, err := netns.GetFromPath(namespace)
	if err != nil {
		return err
	}
	defer cns.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err = netns.Set(cns)
	if err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	err = netlink.LinkDel(link)
	if err != nil {
		return err
	}

	return netns.Set(rootns)
}

//DeleteLinks removes the components of the host interface from the host
func (hi *HostInterface) DeleteLinks() {
	log.Debugf("HostInterface.DeleteLinks()")
	err := hi.delBypassRule()
	if err != nil {
		log.Errorf("failed to delete bypass rule: %v", err)
	}
	err = hi.delBypassRoute()
	if err != nil {
		log.Errorf("failed to delete bypass route: %v", err)
	}

	if hi.mvLink != nil {
		err = netlink.LinkDel(hi.mvLink)
		if err != nil {
			log.Errorf("failed to delete macvlan link: %v", err)
		}
		hi.mvLink = nil
	}

	if hi.vxLink != nil {
		err = netlink.LinkDel(hi.vxLink)
		if err != nil {
			log.Errorf("failed to delete vxlan link: %v", err)
		}
		hi.vxLink = nil
	}
}

func (hi *HostInterface) NumContainers() (int, error) {

	namespaces, err := getNetworkNamespaces()
	if err != nil {
		return -1, err
	}

	numChildren := 0
	for _, ns := range namespaces {
		log.Debugf("checking for interfaces in namespace at %v", ns)
		nsh, err := netns.GetFromPath(ns)
		if err != nil {
			log.WithError(err).Errorf("failed to get namespace at %v", ns)
			return -1, err
		}
		defer func() {
			err := nsh.Close()
			if err != nil {
				log.WithError(err).Errorf("failed to close namespace at %v", ns)
			}
		}()
		nlh, err := netlink.NewHandleAt(nsh, netlink.FAMILY_ALL)
		if err != nil {
			log.Errorf("failed to get netlink handle in namespace at %v", ns)
			return -1, err
		}

		links, err := nlh.LinkList()
		if err != nil {
			return -1, err
		}
		for _, link := range links {
			if link.Attrs().ParentIndex == hi.vxLink.Index {
				if link.Attrs().Index != hi.mvLink.Index {
					numChildren++
				}
			}
		}
	}

	return numChildren, nil
}
