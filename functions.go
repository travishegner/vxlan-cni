package vxlan

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"

	"github.com/vishvananda/netlink"
)

func linkHasAddress(link netlink.Link, address *netlink.Addr) bool {
	addrs, _ := netlink.AddrList(link, 0)

	for _, a := range addrs {
		if a.IP.Equal(address.IP) && a.Mask.String() == address.Mask.String() {
			return true
		}
	}

	return false
}

func linkIndexByName(name string) (int, error) {
	var i int
	dev, err := netlink.LinkByName(name)
	if err == nil {
		i = dev.Attrs().Index
	}
	return i, err
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
