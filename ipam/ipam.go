package ipam

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	log "github.com/sirupsen/logrus"
	cni "github.com/travishegner/go-libcni"
)

//Ipam represents the cni ipam driver our vxlan plugin will use
type Ipam struct {
	bin     string
	timeout time.Duration
}

//New returns a new ipam instance
func New(bin string, timeout time.Duration) *Ipam {
	return &Ipam{
		bin:     bin,
		timeout: timeout,
	}
}

//Add will execute the ipam driver with an ADD command, populating env variables
//for which IP and/or network, link index, and whether to exclude addresses from the
//beginning or end of the range
func (i *Ipam) Add(addr *net.IPNet, linkIndex, xf, xl int) (*cni.Result, error) {
	log.Debugf("i.Add(%v, %v, %v, %v)", addr, linkIndex, xf, xl)
	ctx, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, i.bin)
	cmd.Env = append(os.Environ(), fmt.Sprintf("CNI_ARGS=CIDR=%v;EXCLUDE_FIRST=%v;EXCLUDE_LAST=%v;LINK_INDEX=%v", addr, xf, xl, linkIndex))

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failure while executing ipam: %w", err)
	}

	result := &cni.Result{}
	err = json.Unmarshal(out, result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ipam output: %w", err)
	}

	return result, nil
}

//Del will execute the cni ipam driver with a DEL command pipulating
//env variables for previously issued addresses and their link index
func (i *Ipam) Del(addr *net.IPNet, linkIndex int) error {
	log.Debugf("i.Del(%v, %v)", addr, linkIndex)

	ctx, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, i.bin)
	cmd.Env = append(os.Environ(), fmt.Sprintf("CNI_ARGS=CIDR=%v;LINK_INDEX=%v", addr, linkIndex))

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed while executing ipam delete: %w", err)
	}

	return nil
}
