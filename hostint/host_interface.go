package hostint

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/TrilliumIT/iputil"
	log "github.com/sirupsen/logrus"
	"github.com/travishegner/vxlan-cni/ipam"
	"github.com/travishegner/vxlan-cni/vxlan"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// HostInterface represents the host's connection to the vxlan
// It must be made up of both a "vxlan" interface which participates in the cluster's vxlan
// and a "macvlan" slave of the vxlan interface which acts as the hosts connection to that vxlan
// the hosts address gets isntalled on the macvlan
type HostInterface struct {
	VxlanParams *vxlan.Vxlan
	Gateway     *net.IPNet
	Prefix      *net.IPNet
	ipam        *ipam.Ipam
	vxLink      *netlink.Vxlan
	vxName      string
	mvLink      *netlink.Macvlan
	mvName      string
}

const (
	//DefaultVxlanRouteTable is the table index to store routes for directly connected networks
	//this is necessary because the host prefixes are more specific and otherwise cause packets
	//to be routed for directly connected networks
	DefaultVxlanRouteTable = 192
)

func newHostInterfaceShell(vxlan *vxlan.Vxlan, ipm *ipam.Ipam) (*HostInterface, error) {
	vxName := "vx_" + vxlan.Name
	mvName := "mv_" + vxlan.Name

	cidr, err := netlink.ParseIPNet(vxlan.Cidr)
	if err != nil {
		return nil, err
	}

	return &HostInterface{
		VxlanParams: vxlan,
		Prefix:      iputil.NetworkID(cidr),
		ipam:        ipm,
		vxName:      vxName,
		mvName:      mvName,
	}, nil
}

// GetOrCreate creates required host interfaces if they don't exist, or gets them if they already do
func GetOrCreate(vxlan *vxlan.Vxlan, ipm *ipam.Ipam) (*HostInterface, error) {
	log.Debugf("GetOrCreate(%v, %v)", vxlan, ipm)

	hi, err := Get(vxlan, ipm)
	if err == nil {
		log.Debugf("found existing host interface, returning")
		return hi, nil
	}

	return create(vxlan, ipm)
}

func create(vxlan *vxlan.Vxlan, ipm *ipam.Ipam) (*HostInterface, error) {
	log.Debugf("create(%v, %v)", vxlan, ipm)

	hi, err := newHostInterfaceShell(vxlan, ipm)
	if err != nil {
		return nil, fmt.Errorf("failed to get host interface shell: %w", err)
	}

	err = hi.createVxlanLink()
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to craete vxlan link: %w", err)
	}

	hi.mvLink, err = hi.createMacvlanLink(hi.mvName)
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to create host macvlan link: %w", err)
	}

	gwNet, err := netlink.ParseIPNet(hi.VxlanParams.Cidr)
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to parse vxlan cidr %v: %w", hi.VxlanParams.Cidr, err)
	}
	hi.Prefix = iputil.NetworkID(gwNet)

	result, err := hi.ipam.Add(gwNet, hi.mvLink.Index, hi.VxlanParams.ExcludeFirst, hi.VxlanParams.ExcludeLast)
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to get address %v from ipam for host interface: %w", gwNet, err)
	}

	if len(result.IPs) < 1 || result.IPs[0].Address == "" {
		log.Errorf("no IP was found in ipam result")
		return nil, fmt.Errorf("no IP was found in ipam result")
	}

	gw, err := netlink.ParseIPNet(result.IPs[0].Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address from IPAM result: %w", err)
	}

	log.WithField("GatewayAddress", gw).Debugf("ipam returned address for host interface")

	err = hi.initializeMacvlanLink(hi.mvLink, gw, netns.None(), "")
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to initialize host macvlan link: %w", err)
	}

	hi.Gateway = gw
	err = hi.addBypassRoute()
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed validating/adding bypass route: %w", err)
	}

	err = hi.addBypassRule()
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed validating/adding bpyass rule: %w", err)
	}

	return hi, nil
}

//Get returns an existing valid host interface if the links exist, or an error
//if the host interface is not valid or otherwise paritially configured
//it will delete the remnants to allow a create to be called.
func Get(vxlan *vxlan.Vxlan, ipm *ipam.Ipam) (*HostInterface, error) {
	log.Debugf("Get(%v, %v)", vxlan, ipm)

	hi, err := newHostInterfaceShell(vxlan, ipm)
	if err != nil {
		return nil, fmt.Errorf("failed to get host interface shell: %w", err)
	}

	var link netlink.Link
	link, err = netlink.LinkByName(hi.vxName)
	if err != nil {
		return nil, fmt.Errorf("failed to get vxlan link by name %v: %w", hi.vxName, err)
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
		return nil, fmt.Errorf("failed to get macvlan link by name %v: %w", hi.mvName, err)
	}

	hi.mvLink, ok = link.(*netlink.Macvlan)
	if !ok {
		hi.DeleteLinks()
		return nil, fmt.Errorf("link named %v is not a macvlan", hi.mvName)
	}

	cidr, err := netlink.ParseIPNet(vxlan.Cidr)
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to parse vxlan cidr %v: %w", vxlan.Cidr, err)
	}

	err = hi.setGatewayAttribute(cidr)
	if err != nil {
		hi.DeleteLinks()
		return nil, fmt.Errorf("failed to set gateway for host interface: %w", err)
	}

	return hi, nil
}

//used to set the Gateway attribute, not the actual IP address on the actual link
func (hi *HostInterface) setGatewayAttribute(cidr *net.IPNet) error {
	log.Debugf("setGateway(%v)", cidr)

	addrs, err := netlink.AddrList(hi.mvLink, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	for _, a := range addrs {
		if hi.Prefix.IP.Equal(cidr.IP) {
			if hi.Prefix.Contains(a.IP) {
				hi.Gateway = a.IPNet
				return nil
			}
		}
		if a.IP.Equal(cidr.IP) {
			hi.Gateway = a.IPNet
			return nil
		}
	}

	return fmt.Errorf("expected address %v not found on macvlan link", cidr)
}

func (hi *HostInterface) addBypassRule() error {
	log.Debugf("addBypassRule()")

	r, _ := hi.getBypassRule()
	if r != nil {
		log.Debugf("rule already exists")
		return nil
	}

	log.Debugf("add rule")
	rule := netlink.NewRule()
	rule.Src = hi.Prefix
	rule.Dst = hi.Prefix
	rule.Table = DefaultVxlanRouteTable

	err := netlink.RuleAdd(rule)
	if err != nil {
		return err
	}

	return nil
}

func (hi *HostInterface) getBypassRule() (*netlink.Rule, error) {
	log.Debugf("getBypassRule()")

	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}

	for _, r := range rules {
		if iputil.SubnetEqualSubnet(r.Src, hi.Prefix) && iputil.SubnetEqualSubnet(r.Dst, hi.Prefix) && r.Table == DefaultVxlanRouteTable {
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

	r, _ := hi.getBypassRoute()
	if r != nil {
		return nil
	}

	err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: hi.mvLink.Index,
		Dst:       hi.Prefix,
		Table:     DefaultVxlanRouteTable,
	})
	if err != nil {
		return err
	}

	return nil
}

func (hi *HostInterface) getBypassRoute() (*netlink.Route, error) {
	log.Debugf("getBypassRoute()")

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
		&netlink.Route{
			Table: DefaultVxlanRouteTable,
			Dst:   hi.Prefix,
		},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST,
	)
	if err != nil {
		return nil, err
	}

	for _, r := range routes {
		if r.LinkIndex == hi.mvLink.Index {
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

	err = netlink.RouteDel(r)
	if err != nil {
		return fmt.Errorf("failed to delete bypass route: %w", err)
	}

	return nil
}

func (hi *HostInterface) createVxlanLink() error {
	nl := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: hi.vxName,
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
		dev, err := netlink.LinkByName(vtep)
		if err == nil {
			nl.VtepDevIndex = dev.Attrs().Index
		}
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
		return fmt.Errorf("failed to add vxlan link: %w", err)
	}

	err = netlink.LinkSetUp(nl)
	if err != nil {
		return fmt.Errorf("failed to set vxlan link up: %w", err)
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
		return nil, fmt.Errorf("failed to add macvlan link: %w", err)
	}

	err = netlink.LinkSetUp(nl)
	if err != nil {
		return nil, fmt.Errorf("failed to set macvlan link up: %w", err)
	}

	return nl, nil
}

func (hi *HostInterface) initializeMacvlanLink(nl *netlink.Macvlan, addr *net.IPNet, ns netns.NsHandle, ifname string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rootns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root namespace: %w", err)
	}
	defer rootns.Close()

	if ns.IsOpen() {
		err = netlink.LinkSetNsFd(nl, int(ns))
		if err != nil {
			return fmt.Errorf("failed to move container macvlan into namespace: %w", err)
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		netns.Set(ns)
		defer netns.Set(rootns)

		err = netlink.LinkSetName(nl, ifname)
		if err != nil {
			return fmt.Errorf("failed to set name of link: %w", err)
		}

		err = netlink.LinkSetUp(nl)
		if err != nil {
			return fmt.Errorf("failed to set container macvlan up: %w", err)
		}
	}

	err = netlink.AddrAdd(nl, &netlink.Addr{IPNet: addr})
	if err != nil {
		return fmt.Errorf("failed to add address to macvlan: %w", err)
	}

	if ns.IsOpen() {
		// add default route through host to routing table in container namespace
		defaultDst, _ := netlink.ParseIPNet("0.0.0.0/0")
		err = netlink.RouteAdd(&netlink.Route{
			Dst: defaultDst,
			Gw:  hi.Gateway.IP,
		})
		if err != nil {
			return fmt.Errorf("failed to add default route to container namespace: %w", err)
		}
	}

	return nil
}

//GetOption gets the names vxlan option from the options map
func (hi *HostInterface) GetOption(opt string) (string, bool) {
	val, ok := hi.VxlanParams.Options[opt]
	return val, ok
}

//AddContainerLink adds a new macvlan link to the vxlan link, adds an IP, and puts it in the requested namespace.
func (hi *HostInterface) AddContainerLink(namespace, ifname string, addr *net.IPNet) (int, error) {
	cns, err := netns.GetFromPath(namespace)
	defer func() {
		cns.Close()
	}()
	if err != nil {
		return -1, fmt.Errorf("failed to get container namespace: %w", err)
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
		return -1, fmt.Errorf("failed to create container macvlan: %w", err)
	}

	//addr add, move to namespace
	err = hi.initializeMacvlanLink(cmvl, addr, cns, ifname)
	if err != nil {
		return -1, fmt.Errorf("failed to initialize container macvlan: %w", err)
	}

	return cmvl.Index, nil
}

//DeleteContainerLink deletes the containers interface
func (hi *HostInterface) DeleteContainerLink(namespace, name string) error {
	rootns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root namespace: %w", err)
	}
	defer rootns.Close()

	cns, err := netns.GetFromPath(namespace)
	if err != nil {
		return fmt.Errorf("failed to get container namespace: %w", err)
	}
	defer cns.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err = netns.Set(cns)
	if err != nil {
		return fmt.Errorf("failed to set container namespace: %w", err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get container link by name: %w", err)
	}

	err = netlink.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete container link: %w", err)
	}

	err = netns.Set(rootns)
	if err != nil {
		return fmt.Errorf("failed to set back to root namespace: %w", err)
	}

	return nil
}

//DeleteLinks removes the components of the host interface from the host
func (hi *HostInterface) DeleteLinks() {
	log.Debugf("hi.DeleteLinks()")
	err := hi.delBypassRule()
	if err != nil {
		log.WithError(err).Warningf("failed to delete bypass rule")
	}
	err = hi.delBypassRoute()
	if err != nil {
		log.WithError(err).Warningf("failed to delete bypass route:")
	}

	if hi.mvLink != nil {
		if hi.Gateway != nil {
			err = hi.ipam.Del(hi.Gateway, hi.mvLink.Index)
			if err != nil {
				log.WithError(err).Warningf("failed to delete gateway from IPAM")
			}
		}
		err = netlink.LinkDel(hi.mvLink)
		if err != nil {
			log.WithError(err).Warningf("failed to delete macvlan link")
		}
		hi.mvLink = nil
	}

	if hi.vxLink != nil {
		err = netlink.LinkDel(hi.vxLink)
		if err != nil {
			log.WithError(err).Warningf("failed to delete vxlan link")
		}
		hi.vxLink = nil
	}
}

//NumContainers returns the number of network namespaces with
//child interfaces of the host's vxlan
func (hi *HostInterface) NumContainers() (int, error) {
	namespaces, err := getNetworkNamespaces()
	if err != nil {
		return -1, fmt.Errorf("failed to get network namespaces: %w", err)
	}

	numChildren := 0
	for _, ns := range namespaces {
		nsh, err := netns.GetFromPath(ns)
		if err != nil {
			return -1, fmt.Errorf("failed to get namespace at %v: %w", ns, err)
		}
		defer func() {
			nsh.Close()
		}()
		nlh, err := netlink.NewHandleAt(nsh, netlink.FAMILY_ALL)
		if err != nil {
			return -1, fmt.Errorf("failed to get netlink handle in namespaces at %v: %w", ns, err)
		}

		links, err := nlh.LinkList()
		if err != nil {
			return -1, fmt.Errorf("failed to list links in namespace at %v: %w", ns, err)
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

func getNetworkNamespaces() (map[string]string, error) {
	namespaces := make(map[string]string)

	fileInfos, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to get network namespaces from /proc: %v", err)
	}

	pids := make([]int, 0)

	for _, fi := range fileInfos {
		if !fi.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(fi.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}

	sort.Ints(pids)

	for _, p := range pids {
		name := fmt.Sprintf("/proc/%v/ns/net", p)

		lstat, err := os.Lstat(name)
		if err != nil {
			continue
		}

		if lstat.Mode()&os.ModeSymlink == 0 {
			continue
		}

		ns, err := os.Readlink(name)
		if err != nil {
			continue
		}

		if _, ok := namespaces[ns]; ok {
			continue
		}

		namespaces[ns] = name
	}

	return namespaces, nil
}

//GetMVLinkIndex gets the link index for the host's macvlan
func (hi *HostInterface) GetMVLinkIndex() (int, error) {
	if hi.mvLink == nil {
		return -1, fmt.Errorf("no mcavlan link defined")
	}

	return hi.mvLink.Index, nil
}

//GetVXLinkIndex gets the link index for the host's vxlan
func (hi *HostInterface) GetVXLinkIndex() (int, error) {
	if hi.vxLink == nil {
		return -1, fmt.Errorf("no vxlan link defined")
	}

	return hi.vxLink.Index, nil
}
