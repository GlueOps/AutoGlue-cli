package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultEndpoint = "https://autoglue.glueopshosted.com/api/v1"

type Config struct {
	Profiles []Profile `json:"profiles"`
}

type Profile struct {
	Name        string `json:"name"`
	APIKey      string `json:"api_key"`
	APIEndpoint string `json:"api_endpoint"`
}

type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ClusterListItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Cluster struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	Bastion   *Bastion   `json:"bastion_server"`
	NodePools []NodePool `json:"node_pools"`
}

type Bastion struct {
	Hostname  string `json:"hostname"`
	Status    string `json:"status"`
	PublicIP  string `json:"public_ip_address"`
	PrivateIP string `json:"private_ip_address"`
	SSHKeyID  string `json:"ssh_key_id"`
}

type NodePool struct {
	Servers []Server `json:"servers"`
}

type Server struct {
	Role      string `json:"role"`
	Hostname  string `json:"hostname"`
	Status    string `json:"status"`
	PublicIP  string `json:"public_ip_address"`
	PrivateIP string `json:"private_ip_address"`
	SSHKeyID  string `json:"ssh_key_id"`
}

type Action struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type Run struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type RunDetail struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	Error      string `json:"error"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	FinishedAt string `json:"finished_at"`
}

type APIClient struct {
	Endpoint string
	APIKey   string
	HTTP     *http.Client
}

func main() {
	ctx := context.Background()

	cfgDir, cfgFile, err := configPaths()
	must(err)
	must(os.MkdirAll(cfgDir, 0o755))

	cfg := mustLoadConfig(cfgFile)

	// Parse args
	var selectedProfile string
	if len(os.Args) >= 3 && os.Args[1] == "--profile" {
		selectedProfile = os.Args[2]
	}

	var profile Profile
	if selectedProfile != "" {
		p, ok := cfg.getProfile(selectedProfile)
		if !ok {
			gumStyleForeground("196", fmt.Sprintf("Profile '%s' not found", selectedProfile))
			os.Exit(1)
		}
		profile = p
	} else {
		p, ok := profileMenu(cfgFile, cfg)
		if !ok {
			return
		}
		profile = p
		// reload config because profileMenu may have mutated it
		cfg = mustLoadConfig(cfgFile)
	}

	client := &APIClient{
		Endpoint: strings.TrimRight(profile.APIEndpoint, "/"),
		APIKey:   profile.APIKey,
		HTTP:     &http.Client{Timeout: 20 * time.Second},
	}

	// Validate API key (like /me has .id)
	if err := validateAPIKey(ctx, client); err != nil {
		gumStyleForeground("196", "✗ API key validation failed!")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	browseInfrastructure(ctx, client)
}

// -------------------- Config --------------------

func configPaths() (cfgDir, cfgFile string, err error) {
	// Match bash: $HOME/.config/autoglue-ssh/config.json when possible
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	// Prefer XDG_CONFIG_HOME if set (common on Linux)
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		cfgDir = filepath.Join(xdg, "autoglue-ssh")
	} else if runtimeLikeDarwin() {
		cfgDir = filepath.Join(home, "Library", "Application Support", "autoglue-ssh")
	} else {
		cfgDir = filepath.Join(home, ".config", "autoglue-ssh")
	}
	cfgFile = filepath.Join(cfgDir, "config.json")
	return cfgDir, cfgFile, nil
}

func runtimeLikeDarwin() bool {
	// lightweight check without importing runtime
	return strings.Contains(strings.ToLower(os.Getenv("OSTYPE")), "darwin")
}

func mustLoadConfig(path string) Config {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{Profiles: []Profile{}}
		}
		must(err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		// If file is corrupted, don't silently blow away; surface error.
		must(fmt.Errorf("failed to parse %s: %w", path, err))
	}
	if cfg.Profiles == nil {
		cfg.Profiles = []Profile{}
	}
	return cfg
}

func (c Config) save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// 0600 because it contains API keys
	return os.WriteFile(path, b, 0o600)
}

func (c Config) profileNames() []string {
	out := make([]string, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func (c Config) getProfile(name string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

func (c *Config) addProfile(p Profile) {
	// allow duplicates? bash allowed, but we'll replace by name
	for i := range c.Profiles {
		if c.Profiles[i].Name == p.Name {
			c.Profiles[i] = p
			return
		}
	}
	c.Profiles = append(c.Profiles, p)
}

func (c *Config) deleteProfile(name string) {
	out := make([]Profile, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		if p.Name != name {
			out = append(out, p)
		}
	}
	c.Profiles = out
}

// -------------------- API --------------------

func (a *APIClient) apiCall(ctx context.Context, method, path, orgID string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.Endpoint+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-KEY", a.APIKey)
	if orgID != "" {
		req.Header.Set("X-Org-ID", orgID)
	}
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

func validateAPIKey(ctx context.Context, c *APIClient) error {
	b, _, err := c.apiCall(ctx, http.MethodGet, "/me", "", nil)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("invalid /me response: %w", err)
	}
	if _, ok := m["id"]; !ok {
		return errors.New("missing .id in /me response")
	}
	return nil
}

// glueopshosted.com -> production-captains; else development-captains
func getGHOrg(apiEndpoint string) string {
	if strings.Contains(apiEndpoint, "glueopshosted.com") {
		return "production-captains"
	}
	return "development-captains"
}

// -------------------- Profile UI (gum) --------------------

func profileMenu(cfgFile string, cfg Config) (Profile, bool) {
	for {
		clearScreen()
		gumStyleBorder("AutoGlue SSH - Profile Manager")

		choice := gumChoose("What would you like to do?",
			"Select Profile",
			"Add New Profile",
			"Delete Profile",
			"Quit",
		)
		switch choice {
		case "Select Profile":
			p, ok := selectProfile(cfg)
			if ok {
				return p, true
			}
		case "Add New Profile":
			cfg = addProfileInteractive(cfg)
			must(cfg.save(cfgFile))
		case "Delete Profile":
			cfg = deleteProfileInteractive(cfg)
			must(cfg.save(cfgFile))
		case "Quit", "":
			os.Exit(0)
		}
	}
}

func selectProfile(cfg Config) (Profile, bool) {
	names := cfg.profileNames()
	if len(names) == 0 {
		gumStyleForeground("208", "No profiles configured. Please add one first.")
		sleepSeconds(2)
		return Profile{}, false
	}
	name := gumChoose("Select a profile:", names...)
	if name == "" {
		return Profile{}, false
	}
	p, ok := cfg.getProfile(name)
	return p, ok
}

func addProfileInteractive(cfg Config) Config {
	clearScreen()
	gumStyleBorder("Add New Profile")

	name := gumInput("Profile name (e.g., production)", false)
	if strings.TrimSpace(name) == "" {
		return cfg
	}
	apiKey := gumInput("API Key", true)
	if strings.TrimSpace(apiKey) == "" {
		return cfg
	}

	endpointChoice := gumChoose("Select API endpoint:",
		"https://autoglue.glueopshosted.com/api/v1 (Prod)",
		"https://autoglue.glueopshosted.rocks/api/v1 (Nonprod/Dev)",
		"Custom (enter URL)",
	)
	endpoint := ""
	switch endpointChoice {
	case "https://autoglue.glueopshosted.com/api/v1 (Prod)":
		endpoint = "https://autoglue.glueopshosted.com/api/v1"
	case "https://autoglue.glueopshosted.rocks/api/v1 (Nonprod/Dev)":
		endpoint = "https://autoglue.glueopshosted.rocks/api/v1"
	case "Custom (enter URL)":
		endpoint = gumInput("API Endpoint URL (e.g., https://example.com/api/v1)", false)
	default:
		return cfg
	}
	if strings.TrimSpace(endpoint) == "" {
		return cfg
	}

	fmt.Println("Validating API key...")

	client := &APIClient{
		Endpoint: strings.TrimRight(endpoint, "/"),
		APIKey:   apiKey,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
	}
	if err := validateAPIKey(context.Background(), client); err == nil {
		cfg.addProfile(Profile{Name: name, APIKey: apiKey, APIEndpoint: endpoint})
		gumStyleForeground("82", fmt.Sprintf("✓ Profile '%s' added successfully!", name))
		sleepSeconds(1)
	} else {
		gumStyleForeground("196", "✗ API key validation failed!")
		sleepSeconds(2)
	}
	return cfg
}

func deleteProfileInteractive(cfg Config) Config {
	names := cfg.profileNames()
	if len(names) == 0 {
		gumStyleForeground("208", "No profiles to delete.")
		sleepSeconds(2)
		return cfg
	}
	name := gumChoose("Select profile to delete:", names...)
	if name == "" {
		return cfg
	}
	if gumConfirm(fmt.Sprintf("Delete profile '%s'?", name)) {
		cfg.deleteProfile(name)
		gumStyleForeground("82", "✓ Profile deleted")
		sleepSeconds(1)
	}
	return cfg
}

// -------------------- Main navigation --------------------

func browseInfrastructure(ctx context.Context, client *APIClient) {
	for {
		clearScreen()

		orgs, err := fetchOrgs(ctx, client)
		if err != nil || len(orgs) == 0 {
			gumStyleForeground("196", "No organizations found")
			if err != nil {
				fmt.Println(err.Error())
			}
			os.Exit(1)
		}

		orgNames := make([]string, 0, len(orgs)+1)
		for _, o := range orgs {
			orgNames = append(orgNames, o.Name)
		}
		sort.Strings(orgNames)
		orgNames = append(orgNames, "◀ Back")

		orgSel := gumChoose("Select organization:", orgNames...)
		if orgSel == "" || orgSel == "◀ Back" {
			return
		}

		orgID := ""
		for _, o := range orgs {
			if o.Name == orgSel {
				orgID = o.ID
				break
			}
		}
		if orgID == "" {
			continue
		}

		ghOrg := getGHOrg(client.Endpoint)
		allRepos := listGHReposSuffix(ghOrg, "."+orgSel)

		for {
			clearScreen()

			if len(allRepos) == 0 {
				fmt.Println("No GitHub repositories found for this organization")
				sleepSeconds(2)
				break
			}

			opts := append([]string{}, allRepos...)
			opts = append(opts, "◀ Back")
			repoSel := gumChoose("Select cluster:", opts...)
			if repoSel == "" || repoSel == "◀ Back" {
				break
			}

			clusterName := repoSel

			// Fetch clusters and map to find ID
			clusters, err := fetchClusters(ctx, client, orgID)
			if err != nil {
				gumStyleForeground("196", "Failed to fetch clusters")
				fmt.Println(err.Error())
				sleepSeconds(2)
				continue
			}

			clusterID := ""
			for _, c := range clusters {
				if c.Name == clusterName {
					clusterID = c.ID
					break
				}
			}

			// If cluster doesn't exist in AutoGlue, only offer clone
			if clusterID == "" {
				mode := gumChoose("What would you like to do?",
					fmt.Sprintf("📦 Clone Captain Repository (%s)", repoSel),
					"◀ Back",
				)
				if strings.HasPrefix(mode, "📦") {
					cloneRepoMode(repoSel, ghOrg)
				}
				continue
			}

			cluster, err := fetchCluster(ctx, client, orgID, clusterID)
			if err != nil {
				gumStyleForeground("196", "Failed to fetch cluster details")
				fmt.Println(err.Error())
				sleepSeconds(2)
				continue
			}

			clusterStatus := cluster.Status
			bastionIP := ""
			bastionKeyID := ""
			var servers []Server

			if cluster.Bastion != nil {
				bastionIP = cluster.Bastion.PublicIP
				bastionKeyID = cluster.Bastion.SSHKeyID
				if cluster.Bastion.Hostname != "" {
					servers = append(servers, Server{
						Role:      "BASTION",
						Hostname:  cluster.Bastion.Hostname,
						Status:    ifEmpty(cluster.Bastion.Status, "ready"),
						PublicIP:  ifEmpty(cluster.Bastion.PublicIP, "N/A"),
						PrivateIP: ifEmpty(cluster.Bastion.PrivateIP, "N/A"),
						SSHKeyID:  cluster.Bastion.SSHKeyID,
					})
				}
			}
			for _, np := range cluster.NodePools {
				for _, s := range np.Servers {
					s.Role = strings.ToUpper(s.Role)
					if s.PublicIP == "" {
						s.PublicIP = "N/A"
					}
					if s.PrivateIP == "" {
						s.PrivateIP = "N/A"
					}
					servers = append(servers, s)
				}
			}

			// Collect unique ssh key IDs (bastion + all servers)
			keyIDs := uniqueNonEmpty(append(
				[]string{bastionKeyID},
				extractSSHKeyIDs(servers)...,
			)...)

			// Mode selection loop
			for {
				clearScreen()
				menu := []string{}

				if bastionIP != "" && len(servers) > 0 {
					menu = append(menu, "🔗 SSH to servers", "📡 Port forward to master (6443)", "⚙️ Setup ~/.kube/config")
				}
				menu = append(menu, "⚡ Cluster Actions")
				menu = append(menu, fmt.Sprintf("📦 Clone Captain Repository (%s)", repoSel))
				menu = append(menu, "◀ Back")

				statusDisplay := formatStatusWithEmoji(clusterStatus)

				mode := gumChoose(fmt.Sprintf("Cluster: %s (%s) - What would you like to do?", clusterName, statusDisplay), menu...)
				if mode == "" || mode == "◀ Back" {
					break
				}

				switch mode {
				case "🔗 SSH to servers":
					sshMode(client, orgID, clusterID, bastionIP, servers, strings.Join(keyIDs, " "))
				case "📡 Port forward to master (6443)":
					kubectlMode(client, orgID, clusterID, bastionIP, servers, strings.Join(keyIDs, " "))
				case "⚙️ Setup ~/.kube/config":
					kubeconfigMode(client, orgID, clusterID, bastionIP, servers, strings.Join(keyIDs, " "))
				case "⚡ Cluster Actions":
					clusterActionsMode(ctx, client, orgID, clusterID)
				default:
					if strings.HasPrefix(mode, "📦") {
						cloneRepoMode(repoSel, ghOrg)
					}
				}
			}
		}
	}
}

func fetchOrgs(ctx context.Context, client *APIClient) ([]Org, error) {
	b, code, err := client.apiCall(ctx, http.MethodGet, "/orgs", "", nil)
	if err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("GET /orgs failed: status %d: %s", code, string(b))
	}
	var orgs []Org
	if err := json.Unmarshal(b, &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}

func fetchClusters(ctx context.Context, client *APIClient, orgID string) ([]ClusterListItem, error) {
	b, code, err := client.apiCall(ctx, http.MethodGet, "/clusters", orgID, nil)
	if err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("GET /clusters failed: status %d: %s", code, string(b))
	}
	var clusters []ClusterListItem
	if err := json.Unmarshal(b, &clusters); err != nil {
		return nil, err
	}
	return clusters, nil
}

func fetchCluster(ctx context.Context, client *APIClient, orgID, clusterID string) (*Cluster, error) {
	b, code, err := client.apiCall(ctx, http.MethodGet, "/clusters/"+clusterID, orgID, nil)
	if err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("GET /clusters/%s failed: status %d: %s", clusterID, code, string(b))
	}
	var cluster Cluster
	if err := json.Unmarshal(b, &cluster); err != nil {
		return nil, err
	}
	return &cluster, nil
}

// -------------------- SSH keys / ssh-agent --------------------

func ensureSSHAgent() error {
	// ssh-add -l returns exit code 2 if agent not running
	cmd := exec.Command("ssh-add", "-l")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err == nil {
		return nil
	}
	// If exit code is 2, start agent
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 2 {
		out, err := exec.Command("ssh-agent", "-s").Output()
		if err != nil {
			return err
		}
		// Parse lines like: SSH_AUTH_SOCK=...; export SSH_AUTH_SOCK;
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "SSH_AUTH_SOCK=") {
				val := strings.SplitN(strings.TrimSuffix(line, ";"), "=", 2)
				if len(val) == 2 {
					os.Setenv("SSH_AUTH_SOCK", strings.Split(val[1], ";")[0])
				}
			}
			if strings.HasPrefix(line, "SSH_AGENT_PID=") {
				val := strings.SplitN(strings.TrimSuffix(line, ";"), "=", 2)
				if len(val) == 2 {
					os.Setenv("SSH_AGENT_PID", strings.Split(val[1], ";")[0])
				}
			}
		}
		return nil
	}
	// other exit codes mean agent exists but no keys, etc — fine
	return nil
}

func loadSSHKeys(ctx context.Context, client *APIClient, orgID string, sshKeyIDsSpace string) error {
	ids := strings.Fields(sshKeyIDsSpace)
	if len(ids) == 0 {
		return nil
	}
	if err := ensureSSHAgent(); err != nil {
		return err
	}

	for _, keyID := range uniqueNonEmpty(ids...) {
		b, code, err := client.apiCall(ctx, http.MethodGet, "/ssh/"+keyID+"?reveal=true", orgID, nil)
		if err != nil {
			continue
		}
		if code < 200 || code >= 300 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		pk, _ := m["private_key"].(string)
		if strings.TrimSpace(pk) == "" {
			continue
		}

		cmd := exec.Command("ssh-add", "-")
		cmd.Stdin = strings.NewReader(pk + "\n")
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		_ = cmd.Run()
	}
	return nil
}

// -------------------- Modes --------------------

func sshMode(client *APIClient, orgID, clusterID, bastionIP string, servers []Server, sshKeyIDs string) {
	keyLoaded := false

	for {
		clearScreen()

		display := make([]string, 0, len(servers)+1)
		for _, s := range servers {
			pub := ifEmpty(s.PublicIP, "N/A")
			priv := ifEmpty(s.PrivateIP, "N/A")
			display = append(display, fmt.Sprintf("[%s] %s - Public: %s, Private: %s", s.Role, s.Hostname, pub, priv))
		}
		display = append(display, "◀ Back")

		selection := gumChoose("Select server to SSH into:", display...)
		if selection == "" || selection == "◀ Back" {
			return
		}

		// Extract hostname = second token after [ROLE]
		parts := strings.Fields(selection)
		if len(parts) < 2 {
			continue
		}
		hostname := parts[1]

		var chosen *Server
		for i := range servers {
			if servers[i].Hostname == hostname {
				chosen = &servers[i]
				break
			}
		}
		if chosen == nil {
			continue
		}

		targetIP := chosen.PrivateIP
		if targetIP == "" || targetIP == "N/A" {
			targetIP = chosen.PublicIP
		}

		if !keyLoaded {
			_ = loadSSHKeys(context.Background(), client, orgID, sshKeyIDs)
			keyLoaded = true
		}

		_ = connectSSH(bastionIP, chosen.Role, targetIP)
	}
}

func kubectlMode(client *APIClient, orgID, clusterID, bastionIP string, servers []Server, sshKeyIDs string) {
	keyLoaded := false
	var portForwardCmd *exec.Cmd
	portForwardMaster := ""

	masters := make([]Server, 0)
	for _, s := range servers {
		if strings.ToUpper(s.Role) == "MASTER" {
			masters = append(masters, s)
		}
	}
	if len(masters) == 0 {
		fmt.Println("No master nodes found")
		sleepSeconds(2)
		return
	}

	for {
		clearScreen()

		// If we have a remembered cmd, verify it's still alive
		if portForwardCmd != nil && portForwardCmd.Process != nil {
			if err := portForwardCmd.Process.Signal(os.Signal(nil)); err != nil {
				portForwardCmd = nil
				portForwardMaster = ""
			}
		}

		if portForwardCmd != nil {
			gumStyleForeground("82",
				fmt.Sprintf("✓ Port forward active: localhost:6443 -> %s:6443 (PID: %d)", portForwardMaster, portForwardCmd.Process.Pid))
			fmt.Println()
		}

		opts := []string{}
		for _, m := range masters {
			opts = append(opts, fmt.Sprintf("[%s] %s (%s)", m.Role, m.Hostname, m.Status))
		}
		if portForwardCmd != nil {
			opts = append(opts, "🛑 Stop Port Forward")
		}
		opts = append(opts, "◀ Back")

		selection := gumChoose("Select master node for kubectl port forward:", opts...)
		if selection == "" || selection == "◀ Back" {
			if portForwardCmd != nil && portForwardCmd.Process != nil {
				_ = portForwardCmd.Process.Kill()
			}
			return
		}
		if selection == "🛑 Stop Port Forward" {
			if portForwardCmd != nil && portForwardCmd.Process != nil {
				_ = portForwardCmd.Process.Kill()
			}
			portForwardCmd = nil
			portForwardMaster = ""
			gumStyleForeground("82", "✓ Port forward stopped")
			sleepSeconds(1)
			continue
		}

		// Parse hostname from: [MASTER] host (status)
		host := parseHostFromBracketLine(selection)
		if host == "" {
			continue
		}

		var master *Server
		for i := range masters {
			if masters[i].Hostname == host {
				master = &masters[i]
				break
			}
		}
		if master == nil {
			continue
		}

		targetIP := master.PrivateIP
		if targetIP == "" || targetIP == "N/A" {
			targetIP = master.PublicIP
		}

		if !keyLoaded {
			_ = loadSSHKeys(context.Background(), client, orgID, sshKeyIDs)
			keyLoaded = true
		}

		// Stop existing forward
		if portForwardCmd != nil && portForwardCmd.Process != nil {
			_ = portForwardCmd.Process.Kill()
		}
		portForwardCmd = nil
		portForwardMaster = ""

		// Check if port 6443 is already in use
		if portInUse6443() {
			gumStyleForeground("196", "✗ Port 6443 is already in use")
			fmt.Println()
			if gumConfirm("Kill process on port 6443? (This will stop any existing port forward)") {
				killPort6443()
				sleepSeconds(2)
				if portInUse6443() {
					gumStyleForeground("196", "✗ Failed to kill process on port 6443")
					waitAnyKey()
					continue
				}
			} else {
				continue
			}
		}

		fmt.Printf("Starting port forward: localhost:6443 -> %s:6443\n", host)

		// Rough equivalent to bash's background ssh -L double hop.
		// We keep this process running; user returns to menu; can stop.
		cmd := exec.Command("ssh",
			"-A",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
			"-o", "ExitOnForwardFailure=yes",
			"-L", "6443:localhost:6443",
			"-t", fmt.Sprintf("cluster@%s", bastionIP),
			fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -N -L 6443:localhost:6443 cluster@%s", targetIP),
		)
		cmd.Stdout = io.Discard
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf

		if err := cmd.Start(); err != nil {
			gumStyleForeground("196", "✗ Port forward failed to start")
			fmt.Println(err.Error())
			waitAnyKey()
			continue
		}

		// Give it a moment to fail fast if ExitOnForwardFailure triggers
		time.Sleep(3 * time.Second)
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			gumStyleForeground("196", "✗ Port forward failed to start")
			if errBuf.Len() > 0 {
				fmt.Println()
				fmt.Println("Error details:")
				fmt.Println(errBuf.String())
			}
			waitAnyKey()
			continue
		}

		portForwardCmd = cmd
		portForwardMaster = host
		gumStyleForeground("82", fmt.Sprintf("✓ Port forward started successfully (PID: %d)", cmd.Process.Pid))
		sleepSeconds(1)
	}
}

func kubeconfigMode(client *APIClient, orgID, clusterID, bastionIP string, servers []Server, sshKeyIDs string) {
	masters := make([]Server, 0)
	for _, s := range servers {
		if strings.ToUpper(s.Role) == "MASTER" {
			masters = append(masters, s)
		}
	}
	if len(masters) == 0 {
		fmt.Println("No master nodes found")
		sleepSeconds(2)
		return
	}

	opts := []string{}
	for _, m := range masters {
		opts = append(opts, fmt.Sprintf("[%s] %s (%s)", m.Role, m.Hostname, m.Status))
	}
	opts = append(opts, "◀ Back")

	selection := gumChoose("Select master node to get kubeconfig from:", opts...)
	if selection == "" || selection == "◀ Back" {
		return
	}

	host := parseHostFromBracketLine(selection)
	if host == "" {
		return
	}

	var master *Server
	for i := range masters {
		if masters[i].Hostname == host {
			master = &masters[i]
			break
		}
	}
	if master == nil {
		return
	}

	targetIP := master.PrivateIP
	if targetIP == "" || targetIP == "N/A" {
		targetIP = master.PublicIP
	}

	// Ensure ~/.kube
	home, _ := os.UserHomeDir()
	kubeDir := filepath.Join(home, ".kube")
	_ = os.MkdirAll(kubeDir, 0o755)
	kubeCfg := filepath.Join(kubeDir, "config")

	// Load keys
	_ = loadSSHKeys(context.Background(), client, orgID, sshKeyIDs)

	fmt.Printf("Fetching kubeconfig from %s...\n", host)

	// Equivalent to:
	// ssh -A -t cluster@bastion "ssh cluster@target 'sudo cat /etc/kubernetes/admin.conf'" > ~/.kube/config
	cmd := exec.Command("ssh",
		"-A",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-t", fmt.Sprintf("cluster@%s", bastionIP),
		fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR cluster@%s 'sudo cat /etc/kubernetes/admin.conf'", targetIP),
	)

	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil || out.Len() == 0 {
		fmt.Println("✗ Failed to fetch kubeconfig")
		if errBuf.Len() > 0 {
			fmt.Println(errBuf.String())
		}
		waitAnyKey()
		return
	}

	if err := os.WriteFile(kubeCfg, out.Bytes(), 0o600); err != nil {
		fmt.Println("✗ Failed to write ~/.kube/config:", err.Error())
		waitAnyKey()
		return
	}

	// Update server URL to localhost:6443 (optional)
	if commandExists("kubectl") {
		_ = exec.Command("kubectl", "config", "set-cluster", "kubernetes", "--server=https://127.0.0.1:6443").Run()
		fmt.Println("✓ Kubeconfig saved to ~/.kube/config")
		fmt.Println("✓ Server URL updated to https://127.0.0.1:6443")
	} else {
		fmt.Println("✓ Kubeconfig saved to ~/.kube/config")
		fmt.Println("⚠️  Could not update server URL (kubectl not found?)")
	}

	waitAnyKey()
}

func clusterActionsMode(ctx context.Context, client *APIClient, orgID, clusterID string) {
	for {
		clearScreen()
		choice := gumChoose("Cluster Actions - What would you like to do?",
			"🚀 Trigger",
			"📊 View",
			"◀ Back",
		)
		switch choice {
		case "🚀 Trigger":
			runActionsMode(ctx, client, orgID, clusterID)
		case "📊 View":
			viewRunsMode(ctx, client, orgID, clusterID)
		default:
			return
		}
	}
}

func runActionsMode(ctx context.Context, client *APIClient, orgID, clusterID string) {
	for {
		clearScreen()
		fmt.Println("Fetching available actions...")

		b, code, err := client.apiCall(ctx, http.MethodGet, "/admin/actions", orgID, nil)
		if err != nil || code < 200 || code >= 300 {
			gumStyleForeground("196", "✗ Failed to fetch actions or no actions available")
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println(string(b))
			}
			waitAnyKey()
			return
		}

		var actions []Action
		if err := json.Unmarshal(b, &actions); err != nil || len(actions) == 0 {
			gumStyleForeground("208", "No actions available")
			waitAnyKey()
			return
		}

		display := make([]string, 0, len(actions)+1)
		actionByDisplay := map[string]Action{}
		for _, a := range actions {
			desc := a.Description
			if desc == "" {
				desc = "No description"
			}
			line := fmt.Sprintf("[%s] %s", a.Label, desc)
			display = append(display, line)
			actionByDisplay[line] = a
		}
		sort.Strings(display)
		display = append(display, "◀ Back")

		sel := gumChoose("Select action to run:", display...)
		if sel == "" || sel == "◀ Back" {
			return
		}
		a := actionByDisplay[sel]

		if !gumConfirm("Run action: " + sel + "?") {
			continue
		}

		fmt.Println()
		fmt.Println("Triggering cluster run...")

		path := fmt.Sprintf("/clusters/%s/actions/%s/runs", clusterID, a.ID)
		b, code, err = client.apiCall(ctx, http.MethodPost, path, orgID, bytes.NewReader([]byte(`{}`)))
		if err != nil || code < 200 || code >= 300 {
			gumStyleForeground("196", "✗ Failed to create cluster run")
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println(string(b))
			}
			waitAnyKey()
			continue
		}

		var resp map[string]any
		_ = json.Unmarshal(b, &resp)
		runID, _ := resp["id"].(string)
		status, _ := resp["status"].(string)
		if runID != "" {
			gumStyleForeground("82", "✓ Cluster run created successfully")
			fmt.Println("Run ID:", runID)
			if status != "" {
				fmt.Println("Status:", status)
			}
		} else {
			gumStyleForeground("196", "✗ Failed to create cluster run")
			if msg, _ := resp["message"].(string); msg != "" {
				fmt.Println("Error:", msg)
			} else {
				fmt.Println(string(b))
			}
		}

		waitAnyKey()
	}
}

func viewRunsMode(ctx context.Context, client *APIClient, orgID, clusterID string) {
	for {
		clearScreen()
		fmt.Println("Fetching cluster runs...")

		path := fmt.Sprintf("/clusters/%s/runs", clusterID)
		b, code, err := client.apiCall(ctx, http.MethodGet, path, orgID, nil)
		if err != nil || code < 200 || code >= 300 {
			gumStyleForeground("196", "✗ Failed to fetch cluster runs")
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println(string(b))
			}
			waitAnyKey()
			return
		}

		var runs []Run
		if err := json.Unmarshal(b, &runs); err != nil || len(runs) == 0 {
			gumStyleForeground("208", "No cluster runs found")
			waitAnyKey()
			return
		}

		// Build display
		display := make([]string, 0, len(runs))
		runIDByDisplay := map[string]string{}
		for _, r := range runs {
			icon := "•"
			switch r.Status {
			case "succeeded":
				icon = "✓"
			case "running", "queued":
				icon = "⏳"
			case "failed":
				icon = "✗"
			}
			formatted := formatTimestamp(r.CreatedAt)
			rel := relativeTime(r.CreatedAt)
			line := fmt.Sprintf("[%s %s] %s - %s (%s)", icon, r.Status, r.Action, formatted, rel)
			display = append(display, line)
			runIDByDisplay[line] = r.ID
		}

		display = append(display, "🔄 Refresh", "◀ Back")

		sel := gumChoose("Select run to view details:", display...)
		if sel == "" || sel == "◀ Back" {
			return
		}
		if sel == "🔄 Refresh" {
			continue
		}

		runID := runIDByDisplay[sel]
		if runID == "" {
			continue
		}

		viewRunDetailLoop(ctx, client, orgID, clusterID, runID)
	}
}

func viewRunDetailLoop(ctx context.Context, client *APIClient, orgID, clusterID, runID string) {
	for {
		clearScreen()
		fmt.Println("Fetching run details...")

		path := fmt.Sprintf("/clusters/%s/runs/%s", clusterID, runID)
		b, code, err := client.apiCall(ctx, http.MethodGet, path, orgID, nil)
		if err != nil || code < 200 || code >= 300 {
			gumStyleForeground("196", "✗ Failed to fetch run details")
			if err != nil {
				fmt.Println(err.Error())
			} else {
				fmt.Println(string(b))
			}
			waitAnyKey()
			return
		}

		var d RunDetail
		if err := json.Unmarshal(b, &d); err != nil {
			gumStyleForeground("196", "✗ Failed to parse run details")
			fmt.Println(err.Error())
			waitAnyKey()
			return
		}

		clearScreen()
		gumStyleBorder("Cluster Run Details")
		fmt.Println()

		fmt.Println("ID:", ifEmpty(d.ID, "N/A"))
		fmt.Println("Action:", ifEmpty(d.Action, "N/A"))

		switch d.Status {
		case "succeeded":
			fmt.Print("Status: ")
			gumStyleForeground("82", "✓ "+d.Status)
		case "running", "queued":
			fmt.Print("Status: ")
			gumStyleForeground("208", "⏳ "+d.Status)
		case "failed":
			fmt.Print("Status: ")
			gumStyleForeground("196", "✗ "+d.Status)
		default:
			fmt.Println("Status:", ifEmpty(d.Status, "N/A"))
		}

		fmt.Printf("Created:  %s (%s)\n", formatTimestamp(d.CreatedAt), relativeTime(d.CreatedAt))
		fmt.Printf("Updated:  %s (%s)\n", formatTimestamp(d.UpdatedAt), relativeTime(d.UpdatedAt))
		fmt.Printf("Finished: %s (%s)\n", formatTimestamp(d.FinishedAt), relativeTime(d.FinishedAt))

		if strings.TrimSpace(d.Error) != "" && d.Error != "None" && d.Error != "null" {
			fmt.Println()
			gumStyleForeground("196", "Error:")
			fmt.Println(d.Error)
		}

		if d.Status == "running" || d.Status == "queued" {
			fmt.Println()
			fmt.Println("(Auto-refreshing in 3s... Press any key to return to list)")
			if readKeyWithTimeout(3 * time.Second) {
				return
			}
			continue
		}

		waitAnyKey()
		return
	}
}

// -------------------- Clone repo --------------------

func cloneRepoMode(repoName, org string) {
	if strings.TrimSpace(repoName) == "" {
		return
	}

	if !commandExists("gh") {
		gumStyleForeground("196", "✗ gh not found in PATH")
		waitAnyKey()
		return
	}

	if dirExists(repoName) {
		if !dirExists(filepath.Join(repoName, ".git")) {
			fmt.Printf("Directory '%s' already exists (not a git repository)\n", repoName)
			waitAnyKey()
			return
		}

		fmt.Println("Checking repository status...")
		_ = runInDir(repoName, "git", "fetch", "origin")

		status := captureInDir(repoName, "git", "status", "--porcelain", "--branch")
		hasUncommitted := false
		hasUnpushed := strings.Contains(status, "[ahead ")
		hasUnpulled := strings.Contains(status, "[behind ")

		sc := bufio.NewScanner(strings.NewReader(status))
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "##") && strings.TrimSpace(line) != "" {
				hasUncommitted = true
				break
			}
		}

		if hasUncommitted || hasUnpushed || hasUnpulled {
			fmt.Println()
			if hasUncommitted {
				fmt.Println("⚠️  Repository has uncommitted changes")
			}
			if hasUnpushed {
				fmt.Println("⚠️  Repository has unpushed commits")
			}
			if hasUnpulled {
				fmt.Println("⚠️  Repository has unpulled commits from origin")
			}
			fmt.Println()
		} else {
			fmt.Println("✓ Repository is up to date")
		}
	} else {
		cmd := exec.Command("gh", "repo", "clone", org+"/"+repoName, repoName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println()
			gumStyleForeground("196", "✗ Failed to clone repository")
			waitAnyKey()
			return
		}
		fmt.Println()
		gumStyleForeground("82", "✓ Repository cloned successfully")
	}

	fmt.Println()
	choice := gumChoose("What would you like to do?",
		"🐚 Open shell in repository",
		"◀ Back",
	)
	if choice == "🐚 Open shell in repository" {
		fmt.Println()
		fmt.Printf("Opening shell in %s/ (type 'exit' to return)\n\n", repoName)
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/bash"
		}
		cmd := exec.Command(shell)
		cmd.Dir = repoName
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}
}

// -------------------- SSH connect --------------------

func connectSSH(bastionIP, role, targetIP string) error {
	if strings.ToUpper(role) == "BASTION" {
		cmd := exec.Command("ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
			fmt.Sprintf("cluster@%s", bastionIP),
		)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}

	cmd := exec.Command("ssh",
		"-A",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-t", fmt.Sprintf("cluster@%s", bastionIP),
		fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR cluster@%s", targetIP),
	)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// -------------------- Helpers (time formatting) --------------------

func formatTimestamp(ts string) string {
	if ts == "" || ts == "N/A" || ts == "null" {
		return "N/A"
	}
	// Try RFC3339 parsing (ISO8601)
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// sometimes server returns RFC3339Nano
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return ts
		}
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func relativeTime(ts string) string {
	if ts == "" || ts == "N/A" || ts == "null" {
		return "N/A"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return "unknown"
		}
	}
	d := time.Since(t)
	if d < 0 {
		d = -d
	}
	secs := int(d.Seconds())
	switch {
	case secs < 60:
		return fmt.Sprintf("%ds ago", secs)
	case secs < 3600:
		return fmt.Sprintf("%dm ago", secs/60)
	case secs < 86400:
		return fmt.Sprintf("%dh ago", secs/3600)
	default:
		return fmt.Sprintf("%dd ago", secs/86400)
	}
}

// -------------------- GH repo discovery --------------------

func listGHReposSuffix(ghOrg, suffix string) []string {
	if !commandExists("gh") {
		return nil
	}
	// gh repo list <org> --limit 200 --json name --jq '.[].name'
	out, err := exec.Command("gh", "repo", "list", ghOrg, "--limit", "200", "--json", "name", "--jq", ".[].name").Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var repos []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if strings.HasSuffix(ln, suffix) {
			repos = append(repos, ln)
		}
	}
	sort.Strings(repos)
	return repos
}

// -------------------- Port helpers --------------------

func portInUse6443() bool {
	if !commandExists("lsof") {
		// If lsof missing, assume not in use (best-effort)
		return false
	}
	cmd := exec.Command("lsof", "-ti", ":6443")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return err == nil
}

func killPort6443() {
	if !commandExists("lsof") {
		return
	}
	// lsof -ti :6443 | xargs kill -9
	out, err := exec.Command("lsof", "-ti", ":6443").Output()
	if err != nil {
		return
	}
	pids := strings.Fields(string(out))
	for _, pid := range pids {
		_ = exec.Command("kill", "-9", pid).Run()
	}
}

// -------------------- gum wrappers --------------------

func gumChoose(header string, options ...string) string {
	if !commandExists("gum") {
		// Fallback: print and read
		fmt.Println(header)
		for i, o := range options {
			fmt.Printf("%d) %s\n", i+1, o)
		}
		fmt.Print("> ")
		var idx int
		_, _ = fmt.Scan(&idx)
		if idx <= 0 || idx > len(options) {
			return ""
		}
		return options[idx-1]
	}

	args := []string{"choose", "--header=" + header}
	args = append(args, options...)
	cmd := exec.Command("gum", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	_ = cmd.Run()
	return strings.TrimSpace(out.String())
}

func gumInput(placeholder string, password bool) string {
	if !commandExists("gum") {
		fmt.Print(placeholder + ": ")
		reader := bufio.NewReader(os.Stdin)
		s, _ := reader.ReadString('\n')
		return strings.TrimSpace(s)
	}
	args := []string{"input", "--placeholder", placeholder}
	if password {
		args = append(args, "--password")
	}
	cmd := exec.Command("gum", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	_ = cmd.Run()
	return strings.TrimSpace(out.String())
}

func gumConfirm(msg string) bool {
	if !commandExists("gum") {
		fmt.Print(msg + " (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		s, _ := reader.ReadString('\n')
		s = strings.ToLower(strings.TrimSpace(s))
		return s == "y" || s == "yes"
	}
	cmd := exec.Command("gum", "confirm", msg)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return err == nil
}

func gumStyleBorder(title string) {
	if !commandExists("gum") {
		fmt.Println(title)
		return
	}
	cmd := exec.Command("gum", "style", "--border", "rounded", "--padding", "1 2", "--margin", "1", title)
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

func gumStyleForeground(color, msg string) {
	if !commandExists("gum") {
		fmt.Println(msg)
		return
	}
	cmd := exec.Command("gum", "style", "--foreground", color, msg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

// -------------------- Misc helpers --------------------

func extractSSHKeyIDs(servers []Server) []string {
	var ids []string
	for _, s := range servers {
		if strings.TrimSpace(s.SSHKeyID) != "" {
			ids = append(ids, s.SSHKeyID)
		}
	}
	return ids
}

func uniqueNonEmpty(vals ...string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" || v == "null" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func formatStatusWithEmoji(status string) string {
	switch status {
	case "ready":
		return "✓ ready"
	case "provisioning", "pending":
		return "⏳ " + status
	case "failed":
		return "✗ failed"
	default:
		if status == "" {
			return "unknown"
		}
		return status
	}
}

func parseHostFromBracketLine(line string) string {
	// line: "[MASTER] host (status)"
	// We want token immediately after "]"
	if idx := strings.Index(line, "]"); idx >= 0 && idx+1 < len(line) {
		rest := strings.TrimSpace(line[idx+1:])
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

func ifEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func clearScreen() {
	// best effort
	_ = exec.Command("clear").Run()
}

func sleepSeconds(n int) {
	time.Sleep(time.Duration(n) * time.Second)
}

func waitAnyKey() {
	fmt.Println()
	fmt.Print("Press any key to continue...")
	_, _ = readSingleByte()
	fmt.Println()
}

func readKeyWithTimeout(d time.Duration) bool {
	ch := make(chan bool, 1)
	go func() {
		_, err := readSingleByte()
		ch <- (err == nil)
	}()
	select {
	case ok := <-ch:
		return ok
	case <-time.After(d):
		return false
	}
}

func readSingleByte() (byte, error) {
	// This is not true raw mode; but matches "press any key" enough for many terminals.
	reader := bufio.NewReader(os.Stdin)
	return reader.ReadByte()
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func runInDir(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func captureInDir(dir string, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	_ = cmd.Run()
	return out.String()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err.Error())
		os.Exit(1)
	}
}
