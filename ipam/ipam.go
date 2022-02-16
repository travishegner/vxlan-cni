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

type Ipam struct {
	bin     string
	timeout time.Duration
}

func New(bin string, timeout time.Duration) *Ipam {
	return &Ipam{
		bin:     bin,
		timeout: timeout,
	}
}

func (i *Ipam) Add(addr *net.IPNet, linkIndex, xf, xl int) (*cni.Result, error) {
	log.Debugf("executing IPAM ADD")
	ctx, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, i.bin)
	cmd.Env = append(os.Environ(), fmt.Sprintf("CNI_ARGS=CIDR=%v;EXCLUDE_FIRST=%v;EXCLUDE_LAST=%v;LINK_INDEX=%v", addr, xf, xl, linkIndex))

	out, err := cmd.Output()
	if err != nil {
		log.WithError(err).Debugf("failure while executing ipam")
		return nil, err
	}

	result := &cni.Result{}
	err = json.Unmarshal(out, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (i *Ipam) Del(addr *net.IPNet, linkIndex int) error {
	log.Debugf("executing IPAM DEL")
	//remove /32 route
	ctx, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, i.bin)
	cmd.Env = append(os.Environ(), fmt.Sprintf("CNI_ARGS=CIDR=%v;LINK_INDEX=%v", addr, linkIndex))

	err := cmd.Run()
	if err != nil {
		log.WithError(err).Errorf("error while executing IPAM plugin during DEL")
		return err
	}

	if ctx.Err() == context.DeadlineExceeded {
		log.WithError(ctx.Err()).Errorf("timeout while executing IPAM plugin during DEL")
		return ctx.Err()
	}

	return nil
}
