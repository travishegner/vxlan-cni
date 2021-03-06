package vxlan

import (
	"encoding/json"
	"fmt"

	cni "github.com/travishegner/go-libcni"
)

// Config is the cni config extended with our required attributes
type Config struct {
	*cni.Config
	DefaultNetwork          string   `json:"defaultNetwork"`
	K8sNetworkFromNamespace bool     `json:"k8sNetworkFromNamespace"`
	K8sReadAnnotations      bool     `json:"k8sReadAnnotations"`
	K8sConfigPath           string   `json:"k8sConfigPath"`
	Vxlans                  []*Vxlan `json:"vxlans"`
}

// NewConfig returns a new vxlan config from the byte array
func NewConfig(confBytes []byte) (*Config, error) {
	conf := &Config{}
	err := json.Unmarshal(confBytes, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal confBytes: %w", err)
	}

	return conf, nil
}
