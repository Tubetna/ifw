bash -s -- 2020 <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

PANEL_PORT="${1:-2020}"
APP_DIR="/opt/ifw"
GO_VERSION="1.22.4"
export DEBIAN_FRONTEND=noninteractive

echo "==> [0] Tạo mã nguồn backend + frontend (có Rate Config UI)"
mkdir -p "$APP_DIR/backend" "$APP_DIR/frontend/src"

cat > "$APP_DIR/backend/main.go" <<'GO'
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

type Rule struct {
    ID        string    `json:"id"`
    Proto     string    `json:"proto"`
    FromPort  string    `json:"fromPort"`
    ToIP      string    `json:"toIp"`
    ToPort    string    `json:"toPort"`
    TimeAdded time.Time `json:"timeAdded"`
    Active    bool      `json:"active"`
}

type Config struct {
    DDOSDefense  bool `json:"ddosDefense"`
    TcpSynPerIp  int  `json:"tcpSynPerIp"`
    TcpSynBurst  int  `json:"tcpSynBurst"`
    TcpConnPerIp int  `json:"tcpConnPerIp"`
    UdpPpsPerIp  int  `json:"udpPpsPerIp"`
    UdpBurst     int  `json:"udpBurst"`
}

var (
    rulesFile  = "rules.json"
    configFile = "config.json"
    rules      []Rule
    cfg        Config
    mu         sync.Mutex
)

func defaultConfig() Config {
    return Config{
        DDOSDefense:  true,
        TcpSynPerIp:  150,
        TcpSynBurst:  300,
        TcpConnPerIp: 250,
        UdpPpsPerIp:  8000,
        UdpBurst:     12000,
    }
}

func getenvInt(k string, def int) int {
    if v := os.Getenv(k); v != "" {
        var x int
        if _, err := fmt.Sscanf(v, "%d", &x); err == nil && x > 0 { return x }
    }
    return def
}

func run(cmd string) error {
    log.Println("[CMD]", cmd)
    arr := strings.Fields(cmd)
    out, err := exec.Command(arr[0], arr[1:]...).CombinedOutput()
    if err != nil {
        log.Printf("[ERR] %s: %s", cmd, out)
    }
    return err
}

func protoMap(p string) []string {
    switch strings.ToLower(p) {
    case "both", "all":
        return []string{"tcp", "udp"}
    default:
        return []string{strings.ToLower(p)}
    }
}

func removeRuleSingle(r Rule, proto string) {
    for _, table := range []string{"nat", "filter"} {
        out, _ := exec.Command("iptables-save", "-t", table).Output()
        for _, l := range strings.Split(string(out), "\n") {
            if strings.Contains(l, "gofw-"+r.ID) && strings.Contains(l, proto) {
                line := l
                if strings.HasPrefix(line, "-A") {
                    line = strings.Replace(line, "-A", "-D", 1)
                }
                run(fmt.Sprintf("iptables -t %s %s", table, line))
            }
        }
    }
}

func applyWhitelistBypass(r Rule) {
    id := r.ID
    for _, p := range protoMap(r.Proto) {
        run(fmt.Sprintf(`iptables -I FORWARD -p %s -m set --match-set gofw_white src -d %s --dport %s -m comment --comment gofwwhite-%s -j ACCEPT`,
            p, r.ToIP, r.ToPort, id))
    }
}

func removeWhitelistBypass(r Rule) {
    out, _ := exec.Command("iptables-save", "-t", "filter").Output()
    for _, l := range strings.Split(string(out), "\n") {
        if strings.Contains(l, "gofwwhite-"+r.ID) {
            line := l
            if strings.HasPrefix(line, "-A") {
                line = strings.Replace(line, "-A", "-D", 1)
            }
            run(fmt.Sprintf("iptables -t filter %s", line))
        }
    }
}

func applyDefense(r Rule) {
    if !cfg.DDOSDefense { return }
    id := r.ID
    run(fmt.Sprintf(`iptables -I FORWARD -m conntrack --ctstate INVALID -d %s --dport %s -m comment --comment gofwdef-%s -j DROP`, r.ToIP, r.ToPort, id))
    for _, p := range protoMap(r.Proto) {
        if p == "tcp" {
            run(fmt.Sprintf(`iptables -I FORWARD -p tcp --syn -d %s --dport %s -m hashlimit --hashlimit-above %d/second --hashlimit-burst %d --hashlimit-mode srcip --hashlimit-name syn-%s -m comment --comment gofwdef-%s -j DROP`,
                r.ToIP, r.ToPort, cfg.TcpSynPerIp, cfg.TcpSynBurst, id, id))
            run(fmt.Sprintf(`iptables -I FORWARD -p tcp -d %s --dport %s -m connlimit --connlimit-above %d --connlimit-mask 32 -m comment --comment gofwdef-%s -j DROP`,
                r.ToIP, r.ToPort, cfg.TcpConnPerIp, id))
        }
        if p == "udp" {
            run(fmt.Sprintf(`iptables -I FORWARD -p udp -d %s --dport %s -m conntrack --ctstate NEW -m hashlimit --hashlimit-above %d/second --hashlimit-burst %d --hashlimit-mode srcip --hashlimit-name udpf-%s -m comment --comment gofwdef-%s -j DROP`,
                r.ToIP, r.ToPort, cfg.UdpPpsPerIp, cfg.UdpBurst, id, id))
        }
    }
}

func removeDefense(r Rule) {
    for _, table := range []string{"raw", "mangle", "filter"} {
        out, _ := exec.Command("iptables-save", "-t", table).Output()
        for _, l := range strings.Split(string(out), "\n") {
            if strings.Contains(l, "gofwdef-"+r.ID) || strings.Contains(l, "gofwwhite-"+r.ID) {
                line := l
                if strings.HasPrefix(line, "-A") {
                    line = strings.Replace(line, "-A", "-D", 1)
                }
                run(fmt.Sprintf("iptables -t %s %s", table, line))
            }
        }
    }
}

func applyRule(r Rule) {
    for _, p := range protoMap(r.Proto) {
        removeRuleSingle(r, p)
        run(fmt.Sprintf("iptables -t nat -I PREROUTING -p %s --dport %s -j DNAT --to-destination %s:%s -m comment --comment gofw-%s", p, r.FromPort, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -t nat -I POSTROUTING -p %s -d %s --dport %s -j MASQUERADE -m comment --comment gofw-%s", p, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -I FORWARD -p %s -d %s --dport %s -m comment --comment gofw-%s -j ACCEPT", p, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -I FORWARD -p %s -s %s --sport %s -m comment --comment gofw-%s -j ACCEPT", p, r.ToIP, r.ToPort, r.ID))
    }
    run("iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    applyWhitelistBypass(r)
    applyDefense(r)
}

func removeRule(r Rule) {
    removeDefense(r)
    removeWhitelistBypass(r)
    for _, proto := range protoMap(r.Proto) {
        removeRuleSingle(r, proto)
    }
}

func saveRules() {
    f, _ := os.Create(rulesFile)
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    enc.Encode(rules)
}

func loadRules() {
    f, err := os.Open(rulesFile)
    if err != nil { return }
    defer f.Close()
    json.NewDecoder(f).Decode(&rules)
}

func saveConfig() error {
    f, err := os.Create(configFile)
    if err != nil { return err }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    return enc.Encode(cfg)
}

func loadConfig() {
    // Base defaults
    cfg = defaultConfig()
    // Allow env override on first boot
    cfg.TcpSynPerIp  = getenvInt("DDOS_TCP_SYN_PER_IP", cfg.TcpSynPerIp)
    cfg.TcpSynBurst  = getenvInt("DDOS_TCP_SYN_BURST",  cfg.TcpSynBurst)
    cfg.TcpConnPerIp = getenvInt("DDOS_TCP_CONN_PER_IP",cfg.TcpConnPerIp)
    cfg.UdpPpsPerIp  = getenvInt("DDOS_UDP_PPS_PER_IP", cfg.UdpPpsPerIp)
    cfg.UdpBurst     = getenvInt("DDOS_UDP_BURST",     cfg.UdpBurst)
    if os.Getenv("DDOS_DEFENSE") == "0" { cfg.DDOSDefense = false }

    f, err := os.Open(configFile)
    if err != nil { _ = saveConfig(); return }
    defer f.Close()
    var c Config
    if err := json.NewDecoder(f).Decode(&c); err == nil {
        if c.TcpSynPerIp > 0 { cfg.TcpSynPerIp = c.TcpSynPerIp }
        if c.TcpSynBurst > 0 { cfg.TcpSynBurst = c.TcpSynBurst }
        if c.TcpConnPerIp > 0 { cfg.TcpConnPerIp = c.TcpConnPerIp }
        if c.UdpPpsPerIp > 0 { cfg.UdpPpsPerIp = c.UdpPpsPerIp }
        if c.UdpBurst > 0 { cfg.UdpBurst = c.UdpBurst }
        cfg.DDOSDefense = c.DDOSDefense
    }
    _ = saveConfig()
}

func listIPSet(name string) ([]string, error) {
    out, err := exec.Command("ipset", "list", name, "-o", "save").CombinedOutput()
    if err != nil { return nil, fmt.Errorf("ipset list error: %v\n%s", err, string(out)) }
    ips := []string{}
    for _, l := range strings.Split(string(out), "\n") {
        f := strings.Fields(l)
        if len(f) == 3 && f[0] == "add" && f[1] == name {
            ips = append(ips, f[2])
        }
    }
    return ips, nil
}

type ipReq struct{ IP string `json:"ip"` }

func refreshDefenseAll() {
    // Re-apply defense for all active rules to take new limits immediately
    for _, r := range rules {
        if r.Active {
            removeDefense(r)
            applyDefense(r)
        }
    }
}

func main() {
    var port int
    flag.IntVar(&port, "port", 2020, "Port for admin panel")
    flag.Parse()
    abs, _ := filepath.Abs(rulesFile)
    rulesFile = abs
    absC, _ := filepath.Abs(configFile)
    configFile = absC

    run("ipset create gofw_block hash:ip family inet maxelem 200000 -exist")
    run("ipset create gofw_white hash:ip family inet maxelem 100000 -exist")
    run("iptables -t raw -C PREROUTING -m set --match-set gofw_block src -j DROP || iptables -t raw -I PREROUTING -m set --match-set gofw_block src -j DROP")

    loadConfig()
    loadRules()
    for _, r := range rules { if r.Active { applyRule(r) } }

    mux := http.NewServeMux()
    mux.Handle("/adminsetupfw/assets/", http.StripPrefix("/adminsetupfw/", http.FileServer(http.Dir("public"))))
    mux.Handle("/adminsetupfw/", http.StripPrefix("/adminsetupfw/", http.FileServer(http.Dir("public"))))

    // CRUD rules
    mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock(); defer mu.Unlock()
        if r.Method == "GET" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(rules); return
        }
        if r.Method == "POST" {
            var in Rule
            body, _ := io.ReadAll(r.Body)
            if err := json.Unmarshal(body, &in); err != nil { http.Error(w, "invalid json", 400); return }
            if in.FromPort == "" || in.ToIP == "" || in.ToPort == "" { http.Error(w, "missing", 400); return }
            for _, x := range rules {
                if x.FromPort == in.FromPort && strings.EqualFold(x.Proto, in.Proto) && x.Active {
                    http.Error(w, "Port này đã được forward!", 409); return
                }
            }
            in.ID = fmt.Sprintf("%d", time.Now().UnixNano())
            in.TimeAdded = time.Now()
            in.Active = true
            rules = append(rules, in)
            applyRule(in)
            saveRules()
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(in); return
        }
        http.Error(w, "Method not allowed", 405)
    })
    mux.HandleFunc("/api/rules/", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock(); defer mu.Unlock()
        id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
        if strings.HasSuffix(id, "/toggle") { id = strings.TrimSuffix(id, "/toggle") }
        idx := -1
        for i, x := range rules { if x.ID == id { idx = i } }
        if idx == -1 { http.Error(w, "not found", 404); return }

        if r.Method == "DELETE" {
            removeRule(rules[idx])
            rules = append(rules[:idx], rules[idx+1:]...)
            saveRules()
            w.WriteHeader(204); return
        }
        if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/toggle") {
            rules[idx].Active = !rules[idx].Active
            if rules[idx].Active { applyRule(rules[idx]) } else { removeRule(rules[idx]) }
            saveRules()
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(rules[idx]); return
        }
        if r.Method == "PUT" {
            var in Rule
            body, _ := io.ReadAll(r.Body)
            if err := json.Unmarshal(body, &in); err != nil { http.Error(w, "invalid json", 400); return }
            for i, x := range rules {
                if i != idx && x.FromPort == in.FromPort && strings.EqualFold(x.Proto, in.Proto) && x.Active {
                    http.Error(w, "Port này đã được forward!", 409); return
                }
            }
            wasActive := rules[idx].Active
            if wasActive { removeDefense(rules[idx]); removeWhitelistBypass(rules[idx]) }
            rules[idx].Proto = in.Proto
            rules[idx].FromPort = in.FromPort
            rules[idx].ToIP = in.ToIP
            rules[idx].ToPort = in.ToPort
            if wasActive { applyRule(rules[idx]) }
            saveRules()
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(rules[idx]); return
        }
        http.Error(w, "Method not allowed", 405)
    })

    // Block / Unblock / List blocked
    mux.HandleFunc("/api/block", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" { http.Error(w, "Method not allowed", 405); return }
        var in ipReq
        body, _ := io.ReadAll(r.Body)
        if err := json.Unmarshal(body, &in); err != nil || in.IP == "" { http.Error(w, "invalid json/ip", 400); return }
        if err := run(fmt.Sprintf("ipset add gofw_block %s -exist", in.IP)); err != nil { http.Error(w, "failed", 500); return }
        w.WriteHeader(204)
    })
    mux.HandleFunc("/api/unblock", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" { http.Error(w, "Method not allowed", 405); return }
        var in ipReq
        body, _ := io.ReadAll(r.Body)
        if err := json.Unmarshal(body, &in); err != nil || in.IP == "" { http.Error(w, "invalid json/ip", 400); return }
        if err := run(fmt.Sprintf("ipset del gofw_block %s", in.IP)); err != nil { http.Error(w, "failed", 500); return }
        w.WriteHeader(204)
    })
    mux.HandleFunc("/api/blocked", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "GET" { http.Error(w, "Method not allowed", 405); return }
        ips, err := listIPSet("gofw_block")
        if err != nil { http.Error(w, err.Error(), 500); return }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{"set":"gofw_block","count":len(ips),"ips":ips})
    })

    // Whitelist
    mux.HandleFunc("/api/whitelist", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" { http.Error(w, "Method not allowed", 405); return }
        var in ipReq
        body, _ := io.ReadAll(r.Body)
        if err := json.Unmarshal(body, &in); err != nil || in.IP == "" { http.Error(w, "invalid json/ip", 400); return }
        if err := run(fmt.Sprintf("ipset add gofw_white %s -exist", in.IP)); err != nil { http.Error(w, "failed", 500); return }
        w.WriteHeader(204)
    })
    mux.HandleFunc("/api/unwhitelist", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" { http.Error(w, "Method not allowed", 405); return }
        var in ipReq
        body, _ := io.ReadAll(r.Body)
        if err := json.Unmarshal(body, &in); err != nil || in.IP == "" { http.Error(w, "invalid json/ip", 400); return }
        if err := run(fmt.Sprintf("ipset del gofw_white %s", in.IP)); err != nil { http.Error(w, "failed", 500); return }
        w.WriteHeader(204)
    })
    mux.HandleFunc("/api/whitelisted", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "GET" { http.Error(w, "Method not allowed", 405); return }
        ips, err := listIPSet("gofw_white")
        if err != nil { http.Error(w, err.Error(), 500); return }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{"set":"gofw_white","count":len(ips),"ips":ips})
    })

    // Config endpoints
    mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock(); defer mu.Unlock()
        if r.Method == "GET" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(cfg); return
        }
        if r.Method == "PUT" {
            var in Config
            body, _ := io.ReadAll(r.Body)
            if err := json.Unmarshal(body, &in); err != nil { http.Error(w, "invalid json", 400); return }
            // validate basic
            if in.DDOSDefense {
                if in.TcpSynPerIp <= 0 || in.TcpSynBurst <= 0 || in.TcpConnPerIp <= 0 || in.UdpPpsPerIp <= 0 || in.UdpBurst <= 0 {
                    http.Error(w, "values must be > 0", 400); return
                }
            }
            // apply
            prevDefense := cfg.DDOSDefense
            cfg = in
            if err := saveConfig(); err != nil { http.Error(w, "save failed", 500); return }
            if prevDefense || cfg.DDOSDefense {
                refreshDefenseAll()
            }
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(cfg); return
        }
        http.Error(w, "Method not allowed", 405)
    })

    log.Printf("GoPortPanel chạy tại http://0.0.0.0:%d/adminsetupfw/\n", port)
    http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux)
}
GO

cat > "$APP_DIR/backend/go.mod" <<'GOMOD'
module ifw
go 1.22
GOMOD

cat > "$APP_DIR/frontend/package.json" <<'PKG'
{
  "name": "ifw-ui",
  "version": "1.1.0",
  "scripts": { "dev": "vite", "build": "vite build" },
  "dependencies": { "vue": "^3.4.0" },
  "devDependencies": { "vite": "^5.0.0", "@vitejs/plugin-vue": "^5.0.4" }
}
PKG

cat > "$APP_DIR/frontend/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>IFW PortPanel</title>
  <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Montserrat:wght@600;900&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body{font-family:'Roboto',Arial,sans-serif;background:linear-gradient(135deg,#eaf6ff 0%,#f5f7fa 100%);min-height:100vh}
    .glass{backdrop-filter: blur(8px); background: rgba(255,255,255,0.85);}
  </style>
</head>
<body>
  <div id="app"></div>
  <script type="module" src="/src/main.js"></script>
</body>
</html>
HTML

cat > "$APP_DIR/frontend/src/App.vue" <<'VUE'
<template>
  <div class="container py-5" style="max-width: 1100px;">
    <div class="text-center mb-4">
      <h1 class="fw-bold" style="font-family:'Montserrat',sans-serif;letter-spacing:1.2px;font-size:2.6rem;color:#2c72e8;text-shadow:0 4px 18px #a8c7fa;">
        IFW Forwarding Panel
      </h1>
      <div class="small text-muted mt-2" style="font-size:1.02rem;">
        Forwarding + Anti-DDoS + Block/Whitelist + <b>Rate Config</b> • Thiết kế bởi <b>Tubetna</b>
      </div>
    </div>

    <ul class="nav nav-pills justify-content-center gap-2 mb-4">
      <li class="nav-item"><button class="nav-link" :class="tab==='rules'?'active':''" @click="switchTab('rules')"><i class="bi bi-diagram-3"></i> Forwarding</button></li>
      <li class="nav-item"><button class="nav-link" :class="tab==='blocked'?'active':''" @click="switchTab('blocked')"><i class="bi bi-shield-x"></i> Blocked <span v-if="blocked.length" class="badge bg-danger ms-1">{{ blocked.length }}</span></button></li>
      <li class="nav-item"><button class="nav-link" :class="tab==='whitelist'?'active':''" @click="switchTab('whitelist')"><i class="bi bi-shield-check"></i> Whitelist <span v-if="whitelisted.length" class="badge bg-success ms-1">{{ whitelisted.length }}</span></button></li>
      <li class="nav-item"><button class="nav-link" :class="tab==='rate'?'active':''" @click="switchTab('rate')"><i class="bi bi-speedometer2"></i> Rate Config</button></li>
    </ul>

    <div v-if="alert.msg" class="alert" :class="alert.type" role="alert">{{ alert.msg }}</div>

    <!-- RULES -->
    <div v-show="tab==='rules'" class="card shadow-lg border-0 rounded-4 glass mb-4">
      <div class="card-body p-4">
        <form @submit.prevent="addRule" class="row g-3 align-items-end">
          <div class="col-md-2">
            <label class="form-label fw-semibold">Giao thức</label>
            <select v-model="newRule.proto" class="form-select rounded-3 border-1 shadow-sm">
              <option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label fw-semibold">Cổng VPS</label>
            <input v-model="newRule.fromPort" type="number" min="1" max="65535" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-3">
            <label class="form-label fw-semibold">IP đích</label>
            <input v-model="newRule.toIp" type="text" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-2">
            <label class="form-label fw-semibold">Cổng đích</label>
            <input v-model="newRule.toPort" type="number" min="1" max="65535" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-2 d-grid">
            <button type="submit" class="btn btn-primary rounded-3 shadow fw-bold">
              <i class="bi bi-plus-circle"></i> Lưu Rule
            </button>
          </div>
        </form>
        <div v-if="error" class="alert alert-danger mt-3 py-2 px-3 rounded-3 shadow-sm" role="alert">{{ error }}</div>
      </div>
    </div>

    <div v-show="tab==='rules'" class="card shadow-lg border-0 rounded-4 glass">
      <div class="card-body p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h5 class="card-title fw-bold mb-0">Danh sách Port Forwarding</h5>
          <button class="btn btn-outline-primary btn-sm px-3 rounded-pill shadow-sm" @click="fetchRules"><i class="bi bi-arrow-clockwise"></i> Làm mới</button>
        </div>
        <div class="table-responsive">
          <table class="table align-middle table-hover mb-0">
            <thead class="table-light"><tr>
              <th>Giao thức</th><th>Cổng VPS</th><th>IP đích</th><th>Cổng đích</th><th>Thời gian</th><th>Trạng thái</th><th>Hành động</th>
            </tr></thead>
            <tbody>
              <tr v-if="rules.length === 0"><td colspan="7" class="text-center text-muted">Chưa có rule nào</td></tr>
              <tr v-for="rule in rules" :key="rule.id" :class="{'table-warning':!rule.active}">
                <td><span class="badge bg-primary bg-gradient rounded-pill px-3 shadow-sm">{{ rule.proto.toUpperCase()==='BOTH'?'BOTH':rule.proto.toUpperCase() }}</span></td>
                <td class="fw-semibold">{{ rule.fromPort }}</td>
                <td class="fw-semibold">{{ rule.toIp }}</td>
                <td class="fw-semibold">{{ rule.toPort }}</td>
                <td>{{ formatTime(rule.timeAdded) }}</td>
                <td><span class="badge rounded-pill px-3" :class="rule.active ? 'bg-success' : 'bg-secondary'">{{ rule.active ? 'Hoạt động' : 'Tạm dừng' }}</span></td>
                <td class="d-flex gap-2">
                  <button @click="toggleRule(rule)" class="btn btn-sm shadow-sm" :class="rule.active ? 'btn-outline-warning' : 'btn-outline-success'"><i :class="rule.active ? 'bi bi-pause-fill' : 'bi bi-play-fill'"></i></button>
                  <button @click="editRule(rule)" class="btn btn-sm btn-outline-primary shadow-sm"><i class="bi bi-pencil-square"></i></button>
                  <button @click="deleteRule(rule)" class="btn btn-sm btn-outline-danger shadow-sm"><i class="bi bi-trash"></i></button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- BLOCKED -->
    <div v-show="tab==='blocked'" class="card shadow-lg border-0 rounded-4 glass">
      <div class="card-body p-4">
        <div class="d-flex justify-content-between mb-3">
          <h5 class="fw-bold mb-0"><i class="bi bi-shield-x"></i> IP đang bị chặn</h5>
          <div class="input-group" style="max-width:420px">
            <input v-model="blockIp" type="text" class="form-control" placeholder="Nhập IPv4 để chặn (vd: 1.2.3.4)">
            <button class="btn btn-danger" @click="blockIP"><i class="bi bi-plus"></i> Block</button>
          </div>
        </div>
        <div class="row g-3">
          <div class="col-12 col-md-6 col-lg-4" v-for="ip in blocked" :key="'b-'+ip">
            <div class="card border-0 shadow-sm rounded-3"><div class="card-body d-flex justify-content-between align-items-center">
              <span class="fw-semibold">{{ ip }}</span>
              <button class="btn btn-sm btn-outline-secondary" @click="unblockIP(ip)"><i class="bi bi-unlock"></i> Unblock</button>
            </div></div>
          </div>
          <div v-if="blocked.length===0" class="text-center text-muted">Không có IP nào bị chặn</div>
        </div>
      </div>
    </div>

    <!-- WHITELIST -->
    <div v-show="tab==='whitelist'" class="card shadow-lg border-0 rounded-4 glass">
      <div class="card-body p-4">
        <div class="d-flex justify-content-between mb-3">
          <h5 class="fw-bold mb-0"><i class="bi bi-shield-check"></i> IP Whitelist (bỏ qua hạn chế)</h5>
          <div class="input-group" style="max-width:420px">
            <input v-model="whiteIp" type="text" class="form-control" placeholder="Nhập IPv4 để whitelist">
            <button class="btn btn-success" @click="addWhitelist"><i class="bi bi-plus"></i> Add</button>
          </div>
        </div>
        <div class="row g-3">
          <div class="col-12 col-md-6 col-lg-4" v-for="ip in whitelisted" :key="'w-'+ip">
            <div class="card border-0 shadow-sm rounded-3"><div class="card-body d-flex justify-content-between align-items-center">
              <span class="fw-semibold">{{ ip }}</span>
              <button class="btn btn-sm btn-outline-danger" @click="removeWhitelist(ip)"><i class="bi bi-x-circle"></i> Remove</button>
            </div></div>
          </div>
          <div v-if="whitelisted.length===0" class="text-center text-muted">Chưa có IP nào whitelist</div>
        </div>
      </div>
    </div>

    <!-- RATE CONFIG -->
    <div v-show="tab==='rate'" class="card shadow-lg border-0 rounded-4 glass">
      <div class="card-body p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h5 class="fw-bold mb-0"><i class="bi bi-speedometer2"></i> Cấu hình Rate Limit & Chống DDoS</h5>
          <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" v-model="cfg.ddosDefense" id="swdef">
            <label class="form-check-label" for="swdef">Bật chống DDoS</label>
          </div>
        </div>
        <div class="row g-3">
          <div class="col-md-4">
            <label class="form-label">TCP SYN/giây mỗi IP</label>
            <input type="number" min="10" v-model.number="cfg.tcpSynPerIp" class="form-control" :disabled="!cfg.ddosDefense">
          </div>
          <div class="col-md-4">
            <label class="form-label">TCP SYN Burst</label>
            <input type="number" min="10" v-model.number="cfg.tcpSynBurst" class="form-control" :disabled="!cfg.ddosDefense">
          </div>
          <div class="col-md-4">
            <label class="form-label">TCP Kết nối đồng thời/IP</label>
            <input type="number" min="10" v-model.number="cfg.tcpConnPerIp" class="form-control" :disabled="!cfg.ddosDefense">
          </div>
          <div class="col-md-6">
            <label class="form-label">UDP PPS (NEW) mỗi IP</label>
            <input type="number" min="100" v-model.number="cfg.udpPpsPerIp" class="form-control" :disabled="!cfg.ddosDefense">
          </div>
          <div class="col-md-6">
            <label class="form-label">UDP Burst</label>
            <input type="number" min="100" v-model.number="cfg.udpBurst" class="form-control" :disabled="!cfg.ddosDefense">
          </div>
        </div>
        <div class="text-end mt-3">
          <button class="btn btn-primary" @click="saveCfg"><i class="bi bi-save"></i> Lưu & Áp dụng</button>
        </div>
        <div class="small text-muted mt-2">Lưu ý: chỉ giới hạn <b>TCP SYN</b> và <b>UDP NEW</b>, flow đang chơi không bị ảnh hưởng. Whitelist sẽ bypass toàn bộ.</div>
      </div>
    </div>

    <!-- Modal Edit -->
    <div v-if="editRuleData" class="modal d-block" tabindex="-1" style="background:#0007;">
      <div class="modal-dialog modal-dialog-centered"><div class="modal-content p-3">
        <div class="modal-header"><h5 class="modal-title">Sửa Rule</h5><button type="button" class="btn-close" @click="editRuleData=null"></button></div>
        <div class="modal-body">
          <form @submit.prevent="saveEditRule">
            <div class="mb-2"><label class="form-label">Giao thức</label>
              <select v-model="editRuleData.proto" class="form-select"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select>
            </div>
            <div class="mb-2"><label class="form-label">Cổng nguồn</label><input v-model="editRuleData.fromPort" type="number" class="form-control" required min="1" max="65535"></div>
            <div class="mb-2"><label class="form-label">IP đích</label><input v-model="editRuleData.toIp" type="text" class="form-control" required></div>
            <div class="mb-2"><label class="form-label">Cổng đích</label><input v-model="editRuleData.toPort" type="number" class="form-control" required min="1" max="65535"></div>
            <div class="modal-footer"><button type="submit" class="btn btn-primary">Lưu</button><button type="button" class="btn btn-secondary" @click="editRuleData=null">Đóng</button></div>
          </form>
        </div>
      </div></div>
    </div>

    <div class="text-center mt-4 small text-secondary">
      <span>© 2025 IFW Panel • <b>Forward mượt – Chặn rác nhẹ CPU</b></span>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
const tab = ref('rules')
const rules = ref([])
const error = ref("")
const alert = ref({ msg: "", type: "alert-success" })
const newRule = ref({ proto: 'tcp', fromPort: '', toIp: '', toPort: '' })
const editRuleData = ref(null)
const blocked = ref([]), whitelisted = ref([])
const blockIp = ref(""), whiteIp = ref("")
const cfg = ref({ ddosDefense:true, tcpSynPerIp:150, tcpSynBurst:300, tcpConnPerIp:250, udpPpsPerIp:8000, udpBurst:12000 })

const ipv4ok = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && ip.split('.').every(n=> +n>=0 && +n<=255)
const flash = (msg, type='alert-success') => { alert.value = { msg, type }; setTimeout(()=> alert.value.msg="", 2500) }
const switchTab = (t) => { tab.value = t; if (t==='rules') fetchRules(); if (t==='blocked') fetchBlocked(); if (t==='whitelist') fetchWhitelisted(); if (t==='rate') fetchCfg() }

const fetchRules = async () => { rules.value = await (await fetch('/api/rules')).json() }
const addRule = async () => {
  error.value = ""
  if (!newRule.value.fromPort || !newRule.value.toIp || !newRule.value.toPort) { error.value="Vui lòng nhập đầy đủ thông tin!"; return }
  if (isNaN(+newRule.value.fromPort) || +newRule.value.fromPort<1 || +newRule.value.fromPort>65535) { error.value="Cổng nguồn phải là số từ 1 đến 65535!"; return }
  if (isNaN(+newRule.value.toPort) || +newRule.value.toPort<1 || +newRule.value.toPort>65535) { error.value="Cổng đích phải là số từ 1 đến 65535!"; return }
  if (!ipv4ok(newRule.value.toIp)) { error.value="IP đích không hợp lệ!"; return }
  const body = { proto:newRule.value.proto, fromPort:String(newRule.value.fromPort), toIp:newRule.value.toIp, toPort:String(newRule.value.toPort) }
  const res = await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
  if (res.status===409){ error.value="Port này đã được forward!"; return }
  if (!res.ok){ error.value=(await res.text())||"Không thể tạo rule"; return }
  newRule.value = { proto:'tcp', fromPort:'', toIp:'', toPort:'' }
  flash("Đã tạo rule!"); fetchRules()
}
const toggleRule = async (rule)=>{ const r=await fetch(`/api/rules/${rule.id}/toggle`,{method:'POST'}); flash(r.ok?"Đã cập nhật!":"Không thể cập nhật","alert-"+(r.ok?"success":"danger")); fetchRules() }
const deleteRule = async (rule)=>{ if(confirm('Xóa rule này?')){ const r=await fetch(`/api/rules/${rule.id}`,{method:'DELETE'}); flash(r.ok?"Đã xóa!":"Không thể xóa","alert-"+(r.ok?"success":"danger")); fetchRules() } }
const editRule = (rule)=>{ editRuleData.value = { ...rule } }
const saveEditRule = async ()=> {
  error.value = ""
  if (!editRuleData.value.fromPort || !editRuleData.value.toIp || !editRuleData.value.toPort) { error.value="Vui lòng nhập đầy đủ thông tin!"; return }
  if (isNaN(+editRuleData.value.fromPort) || +editRuleData.value.fromPort<1 || +editRuleData.value.fromPort>65535) { error.value="Cổng nguồn phải là số từ 1 đến 65535!"; return }
  if (isNaN(+editRuleData.value.toPort) || +editRuleData.value.toPort<1 || +editRuleData.value.toPort>65535) { error.value="Cổng đích phải là số từ 1 đến 65535!"; return }
  if (!ipv4ok(editRuleData.value.toIp)) { error.value="IP đích không hợp lệ!"; return }
  const body = { proto:editRuleData.value.proto, fromPort:String(editRuleData.value.fromPort), toIp:editRuleData.value.toIp, toPort:String(editRuleData.value.toPort) }
  const r = await fetch(`/api/rules/${editRuleData.value.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
  if (r.status===409) { error.value="Port này đã được forward!"; return }
  if (!r.ok) { error.value="Không thể cập nhật rule!"; return }
  editRuleData.value=null; flash("Đã lưu rule!"); fetchRules()
}

const fetchBlocked = async ()=>{ const d = await (await fetch('/api/blocked')).json(); blocked.value = d.ips||[] }
const blockIP = async ()=>{ if(!ipv4ok(blockIp.value)){ flash("IP không hợp lệ!","alert-danger"); return } const r=await fetch('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:blockIp.value})}); if(!r.ok){flash("Block thất bại!","alert-danger");return} blockIp.value=""; flash("Đã block IP!"); fetchBlocked() }
const unblockIP = async (ip)=>{ const r=await fetch('/api/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); flash(r.ok?"Đã unblock!":"Unblock thất bại!","alert-"+(r.ok?"success":"danger")); fetchBlocked() }

const fetchWhitelisted = async ()=>{ const d = await (await fetch('/api/whitelisted')).json(); whitelisted.value = d.ips||[] }
const addWhitelist = async ()=>{ if(!ipv4ok(whiteIp.value)){ flash("IP không hợp lệ!","alert-danger"); return } const r=await fetch('/api/whitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:whiteIp.value})}); if(!r.ok){flash("Thêm whitelist thất bại!","alert-danger");return} whiteIp.value=""; flash("Đã whitelist IP!"); fetchWhitelisted() }
const removeWhitelist = async (ip)=>{ const r=await fetch('/api/unwhitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); flash(r.ok?"Đã gỡ whitelist!":"Gỡ whitelist thất bại!","alert-"+(r.ok?"success":"danger")); fetchWhitelisted() }

const fetchCfg = async ()=>{ cfg.value = await (await fetch('/api/config')).json() }
const saveCfg = async ()=>{
  const r = await fetch('/api/config',{ method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(cfg.value) })
  if (!r.ok) { flash("Lưu cấu hình thất bại!", "alert-danger"); return }
  cfg.value = await r.json(); flash("Đã lưu & áp dụng cấu hình!","alert-success")
}

const formatTime = (t)=> t? new Date(t).toLocaleString('vi') : ''
onMounted(()=>{ fetchRules(); fetchBlocked(); fetchWhitelisted(); fetchCfg() })
</script>

<style>
@import "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css";
.card{border-radius:1.2rem!important;box-shadow:0 8px 28px rgba(60,130,255,0.07),0 1.5px 5px rgba(180,200,255,0.09)}
.badge.bg-primary{background:linear-gradient(90deg,#3a89ff 0%,#38e2f1 100%)!important;color:#fff}
.table th,.table td{vertical-align:middle}
.btn:focus,.form-control:focus,.form-select:focus{box-shadow:0 0 0 0.18rem #8bcaff41!important;border-color:#7bb7f7!important}
.nav-pills .nav-link{border-radius:50rem;padding:.5rem 1rem}
.nav-pills .nav-link.active{background:linear-gradient(90deg,#3a89ff 0%,#38e2f1 100%)}
.alert{border:0;border-radius:1rem}
</style>
VUE

cat > "$APP_DIR/frontend/src/main.js" <<'JS'
import { createApp } from 'vue'
import App from './App.vue'
createApp(App).mount('#app')
JS

cat > "$APP_DIR/frontend/vite.config.js" <<'VITE'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({ root: '.', base: '/adminsetupfw/', plugins: [vue()], build: { outDir: 'dist', emptyOutDir: true } })
VITE

echo "==> [1] Cài Go/Node & tối ưu kernel/net + iptables/ipset"
apt-get update -y
apt-get install -y curl git iptables-persistent netfilter-persistent ipset ipset-persistent build-essential ca-certificates

if ! command -v go >/dev/null 2>&1; then
  curl -sL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -xz -C /usr/local
  export PATH="/usr/local/go/bin:$PATH"
  grep -q '/usr/local/go/bin' /root/.profile || echo 'export PATH="/usr/local/go/bin:$PATH"' >> /root/.profile
fi
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
  apt-get install -y nodejs
fi

# Sysctl tối ưu + chống SYN flood + conntrack
cat > /etc/sysctl.d/99-portforward-opt.conf <<SYSCTL
net.core.somaxconn=8192
net.core.netdev_max_backlog=250000
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=7
net.ipv4.tcp_mtu_probing=1
net.ipv4.ip_forward=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_synack_retries=2
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=120
net.netfilter.nf_conntrack_tcp_timeout_established=600
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
SYSCTL
sysctl --system

echo "==> [2] Base rules: reset iptables + hooks raw/mangle + ipset"
iptables -F || true
iptables -t nat -F || true
iptables -t mangle -F || true
iptables -t raw -F || true
iptables -X || true
iptables -t nat -X || true
iptables -t mangle -X || true
iptables -t raw -X || true

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -t mangle -I PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -I FORWARD -p icmp --icmp-type echo-request -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -I FORWARD -p icmp --icmp-type echo-request -j DROP
iptables -I FORWARD -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

ipset create gofw_block hash:ip family inet maxelem 200000 -exist
ipset create gofw_white hash:ip family inet maxelem 100000 -exist
iptables -t raw -C PREROUTING -m set --match-set gofw_block src -j DROP || iptables -t raw -I PREROUTING -m set --match-set gofw_block src -j DROP

iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT || true
iptables -I INPUT -p udp --dport "$PANEL_PORT" -j ACCEPT || true

netfilter-persistent save || true
iptables-save > /etc/iptables/rules.v4
ipset save > /etc/ipset/rules.v4

if command -v ufw >/dev/null 2>&1; then ufw disable || true; fi
if systemctl is-active --quiet firewalld; then systemctl stop firewalld; systemctl disable firewalld; fi

echo "==> [3] Build frontend"
cd "$APP_DIR/frontend"
npm install
npm run build

echo "==> [4] Build backend Go"
cd "$APP_DIR/backend"
rm -rf public
mkdir -p public
cp -r "$APP_DIR/frontend/dist/"* public/ || true

if [ ! -f "$APP_DIR/backend/rules.json" ]; then
  echo '[]' > "$APP_DIR/backend/rules.json"
  chmod 666 "$APP_DIR/backend/rules.json"
fi
if [ ! -f "$APP_DIR/backend/config.json" ]; then
  cat > "$APP_DIR/backend/config.json" <<JSON
{
  "ddosDefense": true,
  "tcpSynPerIp": 150,
  "tcpSynBurst": 300,
  "tcpConnPerIp": 250,
  "udpPpsPerIp": 8000,
  "udpBurst": 12000
}
JSON
  chmod 666 "$APP_DIR/backend/config.json"
fi

export PATH="/usr/local/go/bin:$PATH"
go mod tidy
go build -o portpanel main.go

echo "==> [5] Tạo systemd service"
cat > /etc/systemd/system/ifw.service <<EOF
[Unit]
Description=IFW PortPanel
After=network.target

[Service]
WorkingDirectory=$APP_DIR/backend
# Env chỉ để default lần đầu; sau đó chỉnh trong web (config.json)
Environment=DDOS_DEFENSE=1
Environment=DDOS_TCP_SYN_PER_IP=150
Environment=DDOS_TCP_SYN_BURST=300
Environment=DDOS_TCP_CONN_PER_IP=250
Environment=DDOS_UDP_PPS_PER_IP=8000
Environment=DDOS_UDP_BURST=12000
ExecStart=$APP_DIR/backend/portpanel --port $PANEL_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ifw.service

IP=$(curl -s4 https://api.ipify.org || echo "YOUR_IP")
echo "==> HOÀN TẤT! Panel: http://$IP:$PANEL_PORT/adminsetupfw/"
echo "   • Tab Forwarding: tạo/sửa/tạm dừng/xóa rule"
echo "   • Tab Blocked:    block/unblock IP ngay lập tức"
echo "   • Tab Whitelist:  thêm/gỡ IP bypass hạn chế"
echo "   • Tab Rate Config: bật/tắt chống DDoS + chỉnh ngưỡng, áp dụng tức thì"
echo "==> Tip: dữ liệu lưu tại $APP_DIR/backend/{rules.json,config.json}"

systemctl restart ifw
echo "==> DONE!"
BASH
