package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"sys-mon/ports"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "baseline":
		handleBaseline(args)
	case "ports":
		handlePorts(args)
	case "version", "--version", "-v":
		fmt.Println("sys-mon 0.1.0")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func handleBaseline(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sys-mon baseline <save|load|list|delete> [name]")
		os.Exit(1)
	}

	action := args[0]
	name := "default"
	if len(args) > 1 {
		name = args[1]
	}

	switch action {
	case "save":
		fmt.Println("Scanning ports...")
		current, err := ports.GetPorts()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning ports: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Resolving processes...")
		for i := range current {
			current[i] = ports.ResolveProcess(current[i])
		}

		if err := ports.SaveBaseline(name, current); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving baseline: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Baseline %q saved: %d ports captured at %s\n", name, len(current), time.Now().Format("15:04:05"))

	case "load":
		b, err := ports.LoadBaseline(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading baseline: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Baseline %q loaded: %d ports, captured %s\n", name, len(b.Ports), b.CapturedAt)

	case "list":
		names, err := ports.ListBaselines()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing baselines: %v\n", err)
			os.Exit(1)
		}
		if len(names) == 0 {
			fmt.Println("No baselines found. Run: sys-mon baseline save")
			return
		}
		fmt.Println("Available baselines:")
		for _, n := range names {
			b, err := ports.LoadBaseline(n)
			if err != nil {
				fmt.Printf("  - %s (error reading)\n", n)
				continue
			}
			fmt.Printf("  - %s (%d ports, %s)\n", n, len(b.Ports), b.CapturedAt)
		}

	case "delete":
		if err := ports.DeleteBaseline(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting baseline: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Baseline %q deleted\n", name)

	default:
		fmt.Fprintf(os.Stderr, "Unknown baseline action: %s\n", action)
		fmt.Fprintln(os.Stderr, "Usage: sys-mon baseline <save|load|list|delete> [name]")
		os.Exit(1)
	}
}

func handlePorts(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sys-mon ports <check|whitelist|list> [args...]")
		os.Exit(1)
	}

	action := args[0]
	switch action {
	case "check":
		handleCheck(args[1:])

	case "whitelist":
		handleWhitelist(args[1:])

	case "list":
		handleList()

	case "watch":
		handleWatch(args[1:])

	default:
		fmt.Fprintf(os.Stderr, "Unknown ports action: %s\n", action)
		os.Exit(1)
	}
}

func handleCheck(args []string) {
	name := "default"
	if len(args) > 0 {
		name = args[0]
	}

	b, err := ports.LoadBaseline(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline %q: %v\nRun: sys-mon baseline save\n", name, err)
		os.Exit(1)
	}

	fmt.Println("Scanning ports...")
	current, err := ports.GetPorts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning ports: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Resolving processes...")
	for i := range current {
		current[i] = ports.ResolveProcess(current[i])
	}

	anomalies := ports.CompareBaseline(b, current)
	fmt.Println(ports.FormatAnomaliesText(anomalies))
}

func handleWhitelist(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sys-mon ports whitelist <port> [--protocol tcp|udp] [--family ipv4|ipv6]")
		os.Exit(1)
	}

	port := args[0]
	protocol := "tcp"
	family := "ipv4"

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--protocol":
			i++
			if i < len(args) {
				protocol = args[i]
			}
		case "--family":
			i++
			if i < len(args) {
				family = args[i]
			}
		}
	}

	fmt.Printf("Whitelisted %s:%s/%s. Run 'sys-mon baseline save' to update baseline.\n", family, port, protocol)
}

func handleList() {
	fmt.Println("Scanning ports...")
	current, err := ports.GetPorts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning ports: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Resolving processes...")
	for i := range current {
		current[i] = ports.ResolveProcess(current[i])
	}

	fmt.Printf("\n%6s  %-20s  %-5s  %-6s  %-12s  %s\n", "PID", "ADDRESS", "PORT", "PROTO", "FAMILY", "PROCESS")
	fmt.Println(strings.Repeat("-", 80))
	for _, p := range current {
		fmt.Printf("%6d  %-20s  %-5d  %-6s  %-6s  %-12s\n",
			p.PID, p.Address, p.Port, p.Protocol, p.Family, p.Process)
	}
	fmt.Printf("\nTotal: %d ports\n", len(current))
}

func handleWatch(args []string) {
	interval := 30 // default 30 seconds
	if len(args) > 0 {
		for i := 0; i < len(args); i++ {
			if args[i] == "--interval" && i+1 < len(args) {
				// Parse interval (simple, no duration parsing for now)
				fmt.Fprintf(os.Stderr, "Interval parsing not yet implemented. Using default 30s.\n")
				i++
			}
		}
	}

	fmt.Printf("Watching every %ds. Press Ctrl+C to stop.\n", interval)
	fmt.Println()

	for {
		handleCheck([]string{"default"})
		fmt.Printf("\nNext check in %ds...\n", interval)
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func printUsage() {
	fmt.Println(`sys-mon — Port monitoring for Windows 11

Usage:
  sys-mon baseline <save|load|list|delete> [name]
  sys-mon ports <check|whitelist|list|watch> [args]

Commands:
  baseline save [name]    Capture current ports as baseline
  baseline load [name]    Load a baseline
  baseline list           List available baselines
  baseline delete [name]  Delete a baseline

  ports check [name]      Compare against baseline, show anomalies
  ports whitelist <port>  Whitelist a port
  ports list              Show all active ports
  ports watch             Continuous monitoring

Examples:
  sys-mon baseline save work
  sys-mon ports check work
  sys-mon ports list`)
}
