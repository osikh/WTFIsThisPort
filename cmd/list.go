/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"bytes"
	"encoding/csv"
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
	flagUser   bool
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
		var entries []PortEntry
		switch runtime.GOOS {
        case "windows":
			if flagAll {
				entries = parseNetstatOutput(true, true)
			} else if flagUDP {
				entries = parseNetstatOutput(true, false)
			} else {
				entries = parseNetstatOutput(false, true)
			}
        default:
			if flagAll {
				entries = parseLsofOutput(true, true)
			} else if flagUDP {
				entries = parseLsofOutput(true, false)
			} else {
				entries = parseLsofOutput(false, true)
			}
        }
		printPrettyTable(entries, "🔥 WTF Is This Port?")
	},
}

func init() {
	listCmd.Flags().BoolVarP(&flagUser, "show-user", "i", false, "Show user owning the process (windows only and painfully slow)")
	listCmd.Flags().BoolVarP(&flagUDP, "udp", "u", false, "Show only UDP ports")
    listCmd.Flags().BoolVarP(&flagAll, "all", "a", false, "Show only TCP ports")
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

func parseNetstatOutput(udpOnly bool, tcpOnly bool) []PortEntry {
	cmd := exec.Command("netstat", "-ano")
	out, err := cmd.Output()

	if err != nil {
		fmt.Println("No record found!")
		os.Exit(0)
	}

	var entries []PortEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// skip title or empty lines
		if len(fields) < 4 || fields[0] == "Proto" {
			continue
		}

		var localIpStr = fields[1]
		var foreignIpStr = fields[2]

		// fmt.Println(localIpStr, "\t", foreignIpStr)

		re := regexp.MustCompile(`^(\S+|\*):(\d+|\*)$`)
		localIp := re.FindStringSubmatch(localIpStr)
		foreignIp := re.FindStringSubmatch(foreignIpStr)

		re_brkt := regexp.MustCompile(`^\[(\S+|\*)\]$`)
		lIp := re_brkt.FindStringSubmatch(localIp[1])
		fIp := re_brkt.FindStringSubmatch(foreignIp[1])

		// fmt.Println(localIp[0], "\t",localIp[1], "\t", localIp[2], "\t", lIp)

		entry := PortEntry{
			Proto: fields[0],
			LPort: localIp[2],
			FPort: foreignIp[2],
		}

		if len(lIp) > 0 && lIp[1] != "" {
			entry.Type = "IPV6"
			entry.LAddr = lIp[1]
		} else {
			entry.Type = "IPV4"
			entry.LAddr = localIp[1]
		}

		if len(fIp) > 0 && fIp[1] != "" {
			entry.FAddr = fIp[1]
		} else {
			entry.FAddr = foreignIp[1]
		}

		if entry.Proto == "TCP" {
			entry.State = fields[3]
			entry.PID = fields[4]
		} else {
			entry.PID = fields[3]
		}

		// --------------------------
		// Takes too much time 1 by 1
		// --------------------------
		// // obtain process name and user owned the process
		// cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %s", entry.PID), "/V", "/FO", "CSV")
		// out, err := cmd.Output()
		// if err != nil {
		// 	// fmt.Println("Error:", err)
		// }

		// lines := bytes.Split(out, []byte("\n"))
		// if len(lines) >= 2 {
		// 	// Parse the CSV output
		// 	process_fields := strings.Split(strings.Trim(string(lines[1]), "\""), "\",\"")

		// 	entry.Process = process_fields[0]
		// 	entry.User = process_fields[6]
		// }

		// skip this entry if not required
		if tcpOnly && !udpOnly && entry.Proto != "TCP" {
            continue
        }
        if udpOnly && !tcpOnly && entry.Proto != "UDP" {
            continue
        }

		entries = append(entries, entry)
	}

	// obtain process and user owning that process
	var tasklistCmd = exec.Command("tasklist", "/FO", "CSV")
	if flagUser {
		tasklistCmd = exec.Command("tasklist", "/V", "/FO", "CSV")
	}
	
	tasklistOut, err := tasklistCmd.Output()
	if err != nil {
		fmt.Errorf("failed to run tasklist: %w", err)
	}

	reader := csv.NewReader(bytes.NewReader(tasklistOut))
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Errorf("failed to parse CSV: %w", err)
	}

	// Build a lookup table: PID -> (Name, User)
	processMap := make(map[string][2]string)
	for _, rec := range records[1:] { // skip header
		if len(rec) < 2 {
			continue
		}
		pid := strings.TrimSpace(rec[1])
		name := strings.TrimSpace(rec[0])
		var user = "nil"
		if len(rec) > 6 {
			user = strings.TrimSpace(rec[6])
		}
		processMap[pid] = [2]string{name, user}
	}

	// Match each entry by PID
	for i := range entries {
		if info, ok := processMap[entries[i].PID]; ok {
			entries[i].Process = info[0]
			entries[i].User = info[1]
		} else {
			entries[i].Process = "Unknown"
			entries[i].User = "Unknown"
		}
	}

	return entries
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

		var expression = `^(\S+|\*):(\d+|\*) \((\w+)\)$`
		// this one have foreign ip info extract it
		if strings.Contains(fields[8], "->"){
			expression = `^(\S+|\*):(\d+|\*)->(\S+):(\d+) \((\w+)\)$`
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
        key := fmt.Sprintf("%d-%s-%s-%s-%s", e.Port, e.LAddr, e.PID, e.User, e.State)
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

func cleanIPPort(input string) string {
	colonIndex := strings.LastIndex(input, ":")
	ipPart := input[1:colonIndex]
	portPart := input[colonIndex+1:]
	return ipPart + ":" + portPart
}
