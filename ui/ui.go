package ui

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"nagini/config"
	"nagini/system"
)

// ScriptMetadata holds script metadata information
type ScriptMetadata struct {
	NaGINIVersion   string
	Author          string
	TemplateVersion string
	Info            string
}

// ConfirmWithUser asks user to confirm the detected values
func ConfirmWithUser(info config.SystemInfo) bool {
	fmt.Printf("\n%s=== System Configuration Confirmation ===%s\n", Blue, Reset)
	fmt.Printf("Detected DISK: %s%s%s\n", White, info.Disk, Reset)
	fmt.Printf("Detected INTERFACE: %s%s%s\n", White, info.Interface, Reset)
	fmt.Printf("Detected INTERFACE MAC: %s%s%s\n", White, info.InterfaceMac, Reset)
	fmt.Print("\nAre these values correct? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// GetScriptURL prompts user for the full script URL
func GetScriptURL() (string, error) {
	fmt.Print("Enter the script URL (e.g., https://script.0x7e.eu/b343cbd0): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading script URL: %v", err)
	}

	// Validation (scheme, host) is done by config.ValidateScriptURL in the caller
	return strings.TrimSuffix(strings.TrimSpace(input), "/"), nil
}

// StdinIsTerminal reports whether stdin is an interactive terminal
func StdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// PromptPassphrase reads the decryption passphrase from the terminal without echo
func PromptPassphrase() (string, error) {
	fmt.Print("Enter script passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("error reading passphrase: %v", err)
	}
	return string(passphrase), nil
}

// GetPassword uses script ID as password
func GetPassword(scriptID string) string {
	// Use script ID as password
	password := scriptID
	fmt.Printf("Using script ID as password: %s\n", password)
	return password
}

// ShowInsecureWarning prints a prominent security warning
func ShowInsecureWarning(message string) {
	fmt.Printf("%sWARNING: %s%s\n", Red, message, Reset)
}

// ConfirmExecution asks user to confirm script execution
func ConfirmExecution() bool {
	fmt.Print("\nDo you want to proceed with executing this script? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

// ShowSystemDetectionSection displays the system detection section header
func ShowSystemDetectionSection() {
	fmt.Printf("%s=== Detecting System Information ===%s\n", Blue, Reset)
}

// ShowAutoModeParameters displays provided parameters for automatic mode
func ShowAutoModeParameters(info config.SystemInfo, scriptURL string) {
	fmt.Printf("Using provided parameters:\n")
	fmt.Printf("  DISK: %s%s%s\n", White, info.Disk, Reset)
	fmt.Printf("  INTERFACE: %s%s%s\n", White, info.Interface, Reset)
	fmt.Printf("  INTERFACE MAC: %s%s%s\n", White, info.InterfaceMac, Reset)
	fmt.Printf("  Script URL: %s%s%s\n", White, scriptURL, Reset)
}

// ShowConfigurationSummary displays all configuration before execution
func ShowConfigurationSummary(info config.SystemInfo, password, scriptHash string) {
	fmt.Printf("\n%s=== Configuration Summary ===%s\n", Blue, Reset)
	fmt.Printf("DISK=%s%s%s\n", White, info.Disk, Reset)
	fmt.Printf("INTERFACE=%s%s%s\n", White, info.Interface, Reset)
	fmt.Printf("INTERFACEMAC=%s%s%s\n", White, info.InterfaceMac, Reset)
	fmt.Printf("PASSWORD=%s%s%s\n", White, password, Reset)
	fmt.Printf("Script SHA256: %s%s%s\n", White, scriptHash, Reset)
}

// ShowProvidedParameter displays when a parameter is provided via command line
func ShowProvidedParameter(paramType, value string) {
	fmt.Printf("Using provided %s: %s%s%s\n", paramType, White, value, Reset)
}

// ShowDetectionMessage displays detection messages
func ShowDetectionMessage(what string) {
	fmt.Printf("%sDetecting %s...%s\n", White, what, Reset)
}

// ShowStartAutoInstallation displays message when starting automatic installation
func ShowStartAutoInstallation() {
	fmt.Printf("\n%sAll parameters verified. Starting automatic installation...%s\n", Green, Reset)
}

// ShowVersion displays application version with banner
func ShowVersion(version string) {
	fmt.Printf("%s=============================================================================================%s\n", Blue, Reset)
	fmt.Printf("%s naGINI %s%s%s\n", Blue, White, version, Reset)
	fmt.Printf("%s Arch Linux Webbased Installer%s\n", Blue, Reset)
	fmt.Printf("%s Feedback and Security Issues here: %shttps://github.com/mrwiora/naGINI/issues%s\n", Blue, Cyan, Reset)
	fmt.Printf("%s=============================================================================================%s\n\n", Blue, Reset)
}

// ShowScriptMetadata displays script metadata information
func ShowScriptMetadata(metadata ScriptMetadata) {
	// Only show metadata section if any metadata exists
	if metadata.NaGINIVersion == "" && metadata.Author == "" &&
		metadata.TemplateVersion == "" && metadata.Info == "" {
		return
	}

	fmt.Printf("%s=== Script Information ===%s\n", Green, Reset)
	if metadata.NaGINIVersion != "" {
		fmt.Printf("%sCompatible naGINI Version: %s%s\n", Green, metadata.NaGINIVersion, Reset)
	}
	if metadata.Author != "" {
		fmt.Printf("%sScript Author: %s%s\n", Green, metadata.Author, Reset)
	}
	if metadata.TemplateVersion != "" {
		fmt.Printf("%sTemplate Version: %s%s\n", Green, metadata.TemplateVersion, Reset)
	}
	if metadata.Info != "" {
		fmt.Printf("%sDescription: %s%s\n", Green, metadata.Info, Reset)
	}
	fmt.Printf("%s==============================%s\n\n", Green, Reset)
}

// ShowEncryptionStatus displays encryption information
func ShowEncryptionStatus(wasEncrypted bool) {
	if wasEncrypted {
		fmt.Printf("%s✓ Script was encrypted and has been decrypted successfully%s\n", Green, Reset)
	}
}

// ShowScriptURL displays which script URL is being used
func ShowScriptURL(scriptURL string) {
	if scriptURL != "" {
		fmt.Printf("Using script URL: %s%s%s\n", Cyan, scriptURL, Reset)
	}
}

// ShowModeInfo displays whether running in interactive or automated mode
func ShowModeInfo(isAutoMode bool) {
	if isAutoMode {
		fmt.Printf("Mode: %sAutomated Installation%s\n\n", Green, Reset)
	} else {
		fmt.Printf("Mode: %sInteractive Installation%s\n\n", Yellow, Reset)
	}
}

// ResolveDiskInteractive handles interactive disk resolution with UI feedback
func ResolveDiskInteractive(providedDisk string) (string, error) {
	if providedDisk != "" {
		// User provided disk - validate and show it
		disk, err := system.ResolveDisk(providedDisk)
		if err != nil {
			return "", err
		}
		ShowProvidedParameter("disk", disk)
		return disk, nil
	} else {
		// Auto-detect disk with UI feedback
		ShowDetectionMessage("primary disk")
		disk, err := system.ResolveDisk("")
		if err != nil {
			return "", err
		}
		return disk, nil
	}
}

// ResolveInterfaceInteractive handles interactive interface resolution with UI feedback
func ResolveInterfaceInteractive(providedInterface string) (string, error) {
	if providedInterface != "" {
		// User provided interface - validate and show it
		iface, err := system.ResolveInterface(providedInterface)
		if err != nil {
			return "", err
		}
		ShowProvidedParameter("interface", iface)
		return iface, nil
	} else {
		// Auto-detect interface with UI feedback
		ShowDetectionMessage("network interface")
		iface, err := system.ResolveInterface("")
		if err != nil {
			return "", err
		}
		return iface, nil
	}
}

// ResolveSystemInfoInteractive handles interactive system info resolution for both disk and interface
func ResolveSystemInfoInteractive(providedDisk, providedInterface string) (config.SystemInfo, error) {
	disk, err := ResolveDiskInteractive(providedDisk)
	if err != nil {
		return config.SystemInfo{}, err
	}

	iface, err := ResolveInterfaceInteractive(providedInterface)
	if err != nil {
		return config.SystemInfo{}, err
	}

	// Get MAC address for the interface
	mac, err := system.GetInterfaceMac(iface)
	if err != nil {
		return config.SystemInfo{}, fmt.Errorf("failed to get MAC address: %v", err)
	}

	return config.SystemInfo{
		Disk:         disk,
		Interface:    iface,
		InterfaceMac: mac,
	}, nil
}

// ResolveSystemInfoAuto handles auto mode system info resolution with validation
func ResolveSystemInfoAuto(providedDisk, providedInterface string) (config.SystemInfo, error) {
	disk, iface, mac, err := system.ResolveSystemInfo(providedDisk, providedInterface)
	if err != nil {
		return config.SystemInfo{}, err
	}

	return config.SystemInfo{
		Disk:         disk,
		Interface:    iface,
		InterfaceMac: mac,
	}, nil
}

// ShowNetworkSection displays network setup section header
func ShowNetworkSection() {
	fmt.Printf("\n%s=== System Preparation ===%s\n", Blue, Reset)
}

// ShowScriptSection displays script handling section header
func ShowScriptSection() {
	fmt.Printf("\n%s=== Script Configuration ===%s\n", Blue, Reset)
}

// ShowVerificationSection displays verification section header
func ShowVerificationSection() {
	fmt.Printf("\n%s=== Script Verification ===%s\n", Blue, Reset)
}

// ShowExecutionSection displays execution section header
func ShowExecutionSection() {
	fmt.Printf("\n%s=== Script Execution ===%s\n", Blue, Reset)
}

// ShowCountdown displays a countdown from 5 to 0 in red
func ShowCountdown() {
	fmt.Printf("\nScript execution will begin in: ")
	for i := 5; i >= 1; i-- {
		fmt.Printf("%s%d%s", Red, i, Reset)
		if i > 1 {
			fmt.Printf(" • ")
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Printf(" • %sExecuting now...%s\n\n", Red, Reset)
}

// ShowCompletion displays final success message
func ShowCompletion() {
	fmt.Printf("\n%sArch Linux auto setup completed successfully!%s\n", Green, Reset)
}

// ShowScriptContent displays script content with line numbers for review
// Clears the screen and provides a pager-like interface for scrolling through large scripts
func ShowScriptContent(scriptContent []byte) {
	// Clear the screen
	fmt.Print("\033[H\033[2J")

	fmt.Printf("%s=== SCRIPT CONTENT ===%s\n", Yellow, Reset)
	fmt.Printf("%sThe following script will be executed:%s\n", Yellow, Reset)
	fmt.Printf("%sPress ENTER to scroll, 'q' to finish reviewing%s\n\n", Cyan, Reset)

	// Prepare script content with line numbers
	lines := strings.Split(string(scriptContent), "\n")
	numberedLines := make([]string, len(lines))
	for i, line := range lines {
		numberedLines[i] = fmt.Sprintf("%s%3d:%s %s", Cyan, i+1, Reset, line)
	}

	// Get terminal height (default to 24 if we can't detect)
	terminalHeight := getTerminalHeight()
	linesPerPage := terminalHeight - 4 // Reserve space for header and prompt

	reader := bufio.NewReader(os.Stdin)
	currentLine := 0
	totalLines := len(numberedLines)

	for currentLine < totalLines {
		// Clear screen for each page
		fmt.Print("\033[H\033[2J")

		// Show header
		fmt.Printf("%s=== SCRIPT CONTENT ===%s\n", Yellow, Reset)
		fmt.Printf("%sLines %d-%d of %d%s\n\n", Cyan, currentLine+1, min(currentLine+linesPerPage, totalLines), totalLines, Reset)

		// Display current page
		endLine := min(currentLine+linesPerPage, totalLines)
		for i := currentLine; i < endLine; i++ {
			fmt.Println(numberedLines[i])
		}

		// Show navigation prompt
		if endLine < totalLines {
			fmt.Printf("\n%sPress ENTER for more, 'q' to finish reviewing: %s", Yellow, Reset)
			input, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			input = strings.TrimSpace(strings.ToLower(input))
			if input == "q" || input == "quit" {
				break
			}
			currentLine = endLine
		} else {
			// Last page
			fmt.Printf("\n%s=== END OF SCRIPT ===%s\n", Yellow, Reset)
			fmt.Printf("%sPress ENTER to continue: %s", Green, Reset)
			reader.ReadString('\n')
			break
		}
	}
}

// getTerminalHeight attempts to get the terminal height, returns default if unable
func getTerminalHeight() int {
	// Try to get terminal size using stty
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return 24 // Default terminal height
	}

	dimensions := strings.Fields(string(out))
	if len(dimensions) >= 2 {
		height, err := strconv.Atoi(dimensions[0])
		if err == nil && height > 0 {
			return height
		}
	}

	return 24 // Default terminal height
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
