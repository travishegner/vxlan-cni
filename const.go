package main

import "time"

const (
	//DefaultIPAMTimeout is how long to wait for the IPAM plugin
	DefaultIPAMTimeout = 10 * time.Second

	//DefaultLockPath is the default path to store vxlan locks
	DefaultLockPath = "/tmp"

	//DefaultLockExt is the default extension of the lock file
	DefaultLockExt = ".lock"

	//NetworkAnnotation is the string key where we search for the name of the vxlan to join
	NetworkAnnotation = "vxlan-cni.travishegner.com/NetworkName"

	//AddressAnnotation is the string key where we search for the IP address requested
	AddressAnnotation = "vxlan-cni.travishegner.com/RequestedAddress"
)
