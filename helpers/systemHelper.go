package helpers

import (
	"net"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetMacAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range interfaces {
		// Ignore interfaces without a MAC address
		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}
	return "unknown"
}

func GetIPAddress(c *gin.Context) string {
	ip := c.ClientIP()
	if ip == "" {
		return "unknown"
	}
	return ip
}

func GetSudoUsers() ([]string, error) {
	// Open and read /etc/group file
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return []string{}, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var sudoUsers []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "sudo:") {
			parts := strings.Split(line, ":")

			if parts[3] != "" {
				sudoUsers = strings.Split(parts[3], ",")
			}

			break
		}
	}

	return sudoUsers, nil
}

func GetShells() ([]string, error) {
	// Open and read /etc/shells file
	data, err := os.ReadFile("/etc/shells")
	if err != nil {
		return []string{}, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	shells := []string{"/usr/sbin/nologin"}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") {
			continue
		}

		shells = append(shells, line)
	}

	return shells, nil
}
