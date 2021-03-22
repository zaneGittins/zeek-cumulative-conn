package util

import "net"

// CheckRFC1918 - checks if an IP is an RFC1918 address.
func CheckRFC1918(ip net.IP) bool {

	_, net1, _ := net.ParseCIDR("10.0.0.0/8")
	_, net2, _ := net.ParseCIDR("172.16.0.0/12")
	_, net3, _ := net.ParseCIDR("192.168.0.0/16")

	if net1.Contains(ip) {
		return true
	} else if net2.Contains(ip) {
		return true
	} else if net3.Contains(ip) {
		return true
	}

	return false
}
