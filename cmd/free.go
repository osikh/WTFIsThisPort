/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// freeCmd represents the free command
var freeCmd = &cobra.Command{
	Use:   "free [PORT]",
	Short: "Free a port by killing the process that is using it",
	Long: `This command kills the process holding the specified port.
It should be run with sudo privileges to ensure it can kill processes.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		port := args[0]

		switch runtime.GOOS {
		case "windows":
			freeWindowsPort(port)
		default:
			freeLinuxPort(port)
		}
	},
}

func init() {
	rootCmd.AddCommand(freeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// freeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// freeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func freeLinuxPort(port string) {
	if os.Geteuid() != 0 {
		fmt.Println("WARNING:: This command should be run with sudo.")
		return
	}

	// Execute the lsof command to find the process on the specified port
	cmd := exec.Command("sudo", "lsof", "-t", "-i", ":"+port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error finding processes using port %s:\n%v\n", port, err)
		return
	}

	// Get the process IDs and kill them
	pids := string(output)
	if pids == "" {
		fmt.Printf("No processes are using port %s.\n", port)
		return
	}

	// Split the PIDs and terminate each process
	for _, pid := range strings.Split(pids, "\n") {
		pid = pid // Clean the PID to remove any extra whitespace
		if pid != "" {
			pidInt, err := strconv.Atoi(pid)
			if err != nil {
				fmt.Printf("Invalid PID found: %s\n", pid)
				continue
			}
			fmt.Printf("Killing pid: %d\n", pidInt)

			cmd := exec.Command("sudo", "kill", "-9", strconv.Itoa(pidInt))
			errr := cmd.Run()
			if errr != nil {
				// fmt.Printf("Failed to kill process with PID %d: %v\n", pid, err)
			}
		}
	}
}

func freeWindowsPort(port string) {
	// Check if running with elevated privileges on Windows
	if err := exec.Command("net", "session").Run(); err != nil {
		fmt.Println("WARNING:: This command should be run with elevated privileges.")
		return
	}

	// Use netstat to find processes listening on the specified port
	cmd := exec.Command("cmd", "/C", "netstat -ano | findstr :"+port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error finding processes using port %s:\n%v\n", port, err)
		return
	}

	outStr := string(output)
	if strings.TrimSpace(outStr) == "" {
		fmt.Printf("No processes are using port %s.\n", port)
		return
	}

	// Parse the netstat output to extract PIDs
	lines := strings.Split(outStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pidStr := fields[len(fields)-1]
		pidInt, err := strconv.Atoi(pidStr)
		if err != nil {
			fmt.Printf("Invalid PID found: %s\n", pidStr)
			continue
		}
		fmt.Printf("Killing pid: %d\n", pidInt)

		killCmd := exec.Command("taskkill", "/PID", strconv.Itoa(pidInt), "/F")
		errr := killCmd.Run()
		if errr != nil {
			fmt.Printf("Failed to kill process with PID %d: %v\n", pidInt, errr)
		}
	}
}

func init() {
	// Add the freeCmd to the root command (or another appropriate place in your CLI structure)
	rootCmd.AddCommand(freeCmd)
}
