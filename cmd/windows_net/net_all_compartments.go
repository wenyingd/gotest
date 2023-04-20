package main

import (
	"k8s.io/klog/v2"
	"net"
	"os"
	"strings"

	antreanet "windows_net/third_party/net"
)

func hostInterfaceExists(name string) (bool, error) {
	adapter, err := antreanet.InterfaceByNameInAllCompartments(name)
	if err != nil {
		if strings.Contains(err.Error(), "no such network interface") {
			return false, nil
		}
		return false, err
	}
	klog.InfoS("Found adapter", "name", name, "config", adapter)
	return true, nil
}

func main() {
	name := os.Args[1]
	exists, err := hostInterfaceExists(name)
	if err != nil {
		klog.ErrorS(err, "failed to check network interface existence", "name", name)
		os.Exit(1)
	}
	klog.InfoS("Result of checking network interface existence in all compartments", "result", exists)
	exists2, err := net.InterfaceByName(name)
	if err != nil {
		klog.ErrorS(err, "failed to call net.InterfaceByName", "name", name)
		os.Exit(1)
	}
	klog.InfoS("Result of checking network interface existence with net.InterfaceByName", "result", exists2)
}
