/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	"github.com/spf13/cobra"
)

var (
    flagUDP    bool
    flagAll    bool
	flagSearch  string
)

type PortEntry struct {
    Port     int
    PID      string // Process Id
    Process  string // Command
	UID      string    // User Id
    User     string // User owning the process
	FD 		 string // File descriptor
	Type     string // IPv[4|6]
	Proto	 string // TCP | UDP
    State    string // Listen | Established | Failed
    LAddr    string
	LPort    string
	FAddr    string
	FPort    string
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all listening ports and their owning processes",
	Run: func(cmd *cobra.Command, args []string) {
		switch runtime.GOOS {
        case "windows":
            out, _ := exec.Command("netstat", "-ano").CombinedOutput()
            fmt.Println(string(out))
        default:
            // out, _ := exec.Command("sudo", "lsof", "-nP", "-i", "-a", "-l").CombinedOutput()
            // fmt.Println(string(out))
			if flagAll {
				printPrettyTable(parseLsofOutput(true, true), "🔥 WTF Is This Port?")
			} else if flagUDP {
				printPrettyTable(parseLsofOutput(true, false), "🔥 WTF Is This Port?")
			} else {
				printPrettyTable(parseLsofOutput(false, true), "🔥 WTF Is This Port?")
			}
			
			// if (os.Geteuid() != 0) {
			// 	fmt.Println("\033[33m=> Try running with sudo for full result\033[0m")
			// }
        }
	},
}

func init() {
	listCmd.Flags().BoolVarP(&flagUDP, "udp", "u", false, "Show only UDP ports")
    listCmd.Flags().BoolVarP(&flagAll, "tcp", "t", false, "Show only TCP ports")
	listCmd.Flags().StringVarP(&flagSearch, "look", "l", "", `Search/filter by::
	- Port-> :80 
	- Process-> nginx
	- IP-> 192.168.0.90`)
	rootCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func parseLsofOutput(udpOnly bool, tcpOnly bool) []PortEntry {
	var cmdStr = "sudo lsof -nP -i -a -l"
	if flagSearch != "" {
		cmdStr = fmt.Sprintf("sudo lsof -nP -i -a -l | grep %s", flagSearch)
	}
    cmd := exec.Command("bash", "-c", cmdStr)
    out, err := cmd.Output()

    if err != nil {
		fmt.Println("No record found!")
		os.Exit(0)

        fmt.Println("\033[31m❌ Error running lsof:\033[0m", err)
        os.Exit(1)
    }

    var entries []PortEntry
    scanner := bufio.NewScanner(strings.NewReader(string(out)))
    for scanner.Scan() {
		line := scanner.Text()
        fields := strings.Fields(line)

		if fields[0] == "COMMAND" && fields[1] == "PID" {
			continue
		}

		// get user owning process
		var uid = fields[2]
		usr, err := user.LookupId(uid)
		if err != nil {
			fmt.Println("User not found:", err)
		}

		entry := PortEntry{
            Port:    0,
            PID:     fields[1],
            Process: fields[0],
            UID:     uid,
			User:    usr.Username,
			FD: 	 fields[3],
			Type:    fields[4],
			Proto: 	 fields[7],
        }

		state := "(UNKNOWN)"
		if len(fields) > 9 {
			state = fields[9]
		}
		entry.State = strings.TrimPrefix(strings.TrimSuffix(state, ")"), "(")
		if entry.State == "UNKNOWN" {
			entry.State = ""
		}

		var expression = `^(\S+):(\d+) \((\w+)\)$`
		// this one have foreign ip info extract it
		if strings.Contains(fields[8], "->"){
			expression = `^(\S+):(\d+)->(\S+):(\d+) \((\w+)\)$`
		}

		re := regexp.MustCompile(expression)
		matches := re.FindStringSubmatch(fields[8]+" "+state)

		if len(matches) > 0 {

			// Determine if it's IPv4 or IPv6 based on the address format
			var connType = "IPv4"
			if strings.Contains(matches[1], ":") {
				connType = "IPv6"
			}

			// Local Address & Port (must be present)
			localAddress := matches[1]
			localPort := matches[2]

			// Handle missing Foreign Address / Foreign Port (if not matched, keep empty)
			var foreignAddress, foreignPort string
			if len(matches) > 4 && matches[3] != "" && len(matches[3]) > 0 {
				foreignAddress = matches[3]
				foreignPort = matches[4]
			} else {
				foreignAddress = ""
				foreignPort = ""
			}

			// Handle special cases for `*` and `[::1]`
			// if localAddress == "*" {
			// 	localAddress = "0.0.0.0" // Replace * with 0.0.0.0 for IPv4
			// }
			if strings.Contains(localAddress, "[::1]") {
				localAddress = "::1" // Remove brackets for IPv6 loopback address
			}

			entry.Type = connType
			entry.LAddr = localAddress
			entry.LPort = localPort
			entry.FAddr = foreignAddress
			entry.FPort = foreignPort
		} else {
			entry.Type  = ""
			entry.LAddr = ""
			entry.LPort = ""
			entry.FAddr = ""
			entry.FPort = ""
		}

		if tcpOnly && !udpOnly && entry.Proto != "TCP" {
            continue
        }
        if udpOnly && !tcpOnly && entry.Proto != "UDP" {
            continue
        }

		entries = append(entries, entry)
	}

	return entries
}

func printPrettyTable(entries []PortEntry, title string) {
    t := table.NewWriter()
    t.SetOutputMirror(os.Stdout)
    t.SetTitle(title)
    t.AppendHeader(table.Row{"Proto", "Type", "Local Address", "Foreign Address", "State", "Process"})

	t.SetRowPainter(table.RowPainter(func(row table.Row) text.Colors {
		var color = text.Colors{text.FgRed}
		switch row[4] {
			case "LISTEN":
				return text.Colors{text.FgGreen}
			case "ESTABLISHED":
				return text.Colors{text.FgBlue}
		}
		return color
	}))
	

    seen := make(map[string]bool)
    for _, e := range entries {
        key := fmt.Sprintf("%d-%s-%s-%s", e.Port, e.PID, e.User, e.State)
        if seen[key] {
            continue // skip if key matches
        }
        seen[key] = true // to avoid duplicate

		var foreignAddr = ""
		if len(e.FAddr) > 0 {
			foreignAddr = e.FAddr+":"+e.FPort
		}
        
		var r = table.Row{e.Proto, e.Type, e.LAddr+":"+e.LPort, foreignAddr, e.State, e.PID+"/"+e.Process+"@"+e.User}
		t.AppendRow(r)
    }

    t.Render()
}
