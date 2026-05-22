package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/secureNqwer/zerolink-server/server"
)

func main() {
	cfgPath := flag.String("config", "server.json", "path to server config JSON")
	flag.Parse()

	cfg := server.DefaultServerConfig()
	if data, err := os.ReadFile(*cfgPath); err == nil {
		if err := json.Unmarshal(data, cfg); err != nil {
			panic("invalid config: " + err.Error())
		}
		fmt.Printf("Config loaded: zt_network=%q\n", cfg.ZTNetwork)
	} else {
		fmt.Printf("\nNo config file (%s) found.\n", *cfgPath)
		cfg = runServerSetup()
		data, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile(*cfgPath, data, 0644)
		fmt.Printf("Config saved to %s\n\n", *cfgPath)
	}

	// ─── Create server ─────────────────────────────────────────────────
	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatal("create server:", err)
	}

	// ─── Print addresses ───────────────────────────────────────────────
	port := portFromAddr(cfg.ListenAddr)
	fmt.Println("\n─── Messenger Server ───")
	fmt.Printf("  Port: %s\n\n", port)

	// ZeroTier address
	ztAddrs := detectSystemZTNetworks()
	if len(ztAddrs) > 0 {
		fmt.Println("  ZeroTier (for internet):")
		for _, n := range ztAddrs {
			fmt.Printf("    %s\n", net.JoinHostPort(n, port))
		}
	}

	// LAN address
	ifaceIP := primaryIP()
	fmt.Printf("  LAN (same Wi-Fi): %s\n", net.JoinHostPort(ifaceIP, port))
	fmt.Println()

	// ─── Graceful shutdown ─────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		fmt.Println("\nshutting down...")
		if err := srv.Stop(ctx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}
	}()

	if err := srv.Start(); err != nil {
		log.Println("server stopped:", err)
	}
}

// systemZTIP returns the ZT IP for a specific network ID (or the first found)
func systemZTIP(networkID string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if len(iface.Name) < 2 || (iface.Name[:2] != "zt" && iface.Name[:2] != "ZW") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			return ip4.String()
		}
	}
	return ""
}

func detectSystemZTNetworks() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var nets []string
	seen := make(map[string]bool)
	for _, iface := range ifaces {
		if len(iface.Name) < 2 || (iface.Name[:2] != "zt" && iface.Name[:2] != "ZW") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // skip IPv6
			}
			ip := ip4.String()
			if !seen[ip] {
				seen[ip] = true
				nets = append(nets, ip)
			}
		}
	}
	return nets
}

func runServerSetup() *server.ServerConfig {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\n─── Server Setup ───")
	fmt.Println()

	port := ""
	for {
		fmt.Print("Port [8080]: ")
		p, _ := reader.ReadString('\n')
		p = strings.TrimSpace(p)
		if p == "" {
			p = "8080"
		}
		port = p
		break
	}

	secret := ""
	for {
		fmt.Print("Token secret (for user auth): ")
		s, _ := reader.ReadString('\n')
		s = strings.TrimSpace(s)
		if s == "" {
			fmt.Println("Secret cannot be empty")
			continue
		}
		secret = s
		break
	}

	ztNetwork := ""
	fmt.Print("ZeroTier network ID (press Enter to skip): ")
	z, _ := reader.ReadString('\n')
	ztNetwork = strings.TrimSpace(z)

	cfg := server.DefaultServerConfig()
	cfg.ListenAddr = ":" + port
	cfg.TokenSecret = secret
	cfg.ZTNetwork = ztNetwork

	fmt.Println()
	return cfg
}

func primaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			return ip.String()
		}
	}
	return "127.0.0.1"
}

func portFromAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "8080"
	}
	return port
}
