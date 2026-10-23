package network

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// RunDHCPCD starts DHCP client on the specified interface in the background
// and configures time synchronization
func RunDHCPCD(iface string) error {
	fmt.Printf("Starting DHCP client on interface %s in background...\n", iface)

	// Stop any existing dhcpcd processes in background
	go func() {
		exec.Command("killall", "dhcpcd").Run()
	}()

	// Start dhcpcd on the interface in background
	cmd := exec.Command("dhcpcd", iface)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start dhcpcd: %v", err)
	}

	fmt.Printf("DHCP client started in background (PID: %d)\n", cmd.Process.Pid)

	// Configure time synchronization
	fmt.Println("Configuring time synchronization...")

	// Enable NTP
	if err := exec.Command("timedatectl", "set-ntp", "true").Run(); err != nil {
		fmt.Printf("Warning: failed to enable NTP: %v\n", err)
	} else {
		fmt.Println("NTP enabled successfully")
	}

	// Restart systemd-timesyncd
	if err := exec.Command("systemctl", "restart", "systemd-timesyncd").Run(); err != nil {
		fmt.Printf("Warning: failed to restart systemd-timesyncd: %v\n", err)
	} else {
		fmt.Println("systemd-timesyncd restarted successfully")
	}

	return nil
}

// WaitForTimeSync waits until systemd-timesyncd reports a synchronised clock, at most timeout.
// HTTPS certificate validation fails with a wrong clock, so this runs before the download.
// It never fails: without NTP access the download is attempted anyway.
func WaitForTimeSync(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	announced := false
	for {
		out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
		if errors.Is(err, exec.ErrNotFound) {
			return // no systemd-timedated; nothing to wait for
		}
		if err == nil && strings.TrimSpace(string(out)) == "yes" {
			if announced {
				fmt.Println("System clock synchronised")
			}
			return
		}
		if time.Now().After(deadline) {
			fmt.Printf("Warning: system clock not synchronised via NTP (now %s); HTTPS may fail if it is wrong\n",
				time.Now().UTC().Format(time.RFC3339))
			return
		}
		if !announced {
			fmt.Println("Waiting for NTP time synchronisation...")
			announced = true
		}
		time.Sleep(time.Second)
	}
}
