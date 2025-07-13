#!/usr/bin/env bash
# Go+Vue3 PortPanel tối ưu forwarding TCP+UDP - không anti-ddos, chỉ hiệu suất!

set -euo pipefail

PANEL_PORT="${1:-2020}"
APP_DIR="/opt/goportpanel"
GO_VERSION="1.22.4"

echo "==> [0] Cài Go, Node, git, iptables-persistent"
apt-get update -y
apt-get install -y curl git iptables-persistent build-essential ethtool

echo "==> [1] Tối ưu kernel forwarding"
cat <<EOF | tee -a /etc/sysctl.conf
net.ipv4.ip_forward=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=32768
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.udp_rmem_min=65536
net.ipv4.udp_wmem_min=65536
net.ipv4.tcp_fin_timeout=7
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_mtu_probing=1
EOF
sysctl -p

echo "==> [2] Tối ưu card mạng (nếu hỗ trợ)"
ethtool -K eth0 gro off gso off tso off || true

echo "==> [3] Tạo project code"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/backend"
mkdir -p "$APP_DIR/frontend/src"
cd "$APP_DIR"

echo "==> [4] Sinh source code backend Go"
cat > "$APP_DIR/backend/main.go" <<'GO'
package main

import (
    "encoding/json"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "sync"
    "time"
    "flag"
    "fmt"
    "strings"
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

var (
    rulesFile = "rules.json"
    rules     []Rule
    mu        sync.Mutex
)

func run(cmd string) error {
    log.Println("[CMD]", cmd)
    arr := strings.Fields(cmd)
    return exec.Command(arr[0], arr[1:]...).Run()
}

func protoMap(p string) []string {
    switch p {
    case "both", "all":
        return []string{"tcp", "udp"}
    default:
        return []string{p}
    }
}

func applyRule(r Rule) {
    for _, p := range protoMap(r.Proto) {
        run(fmt.Sprintf("iptables -t nat -A PREROUTING -p %s --dport %s -j DNAT --to-destination %s:%s -m comment --comment gofw-%s", p, r.FromPort, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -t nat -A POSTROUTING -p %s -d %s --dport %s -j MASQUERADE -m comment --comment gofw-%s", p, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -I FORWARD -p %s -d %s --dport %s -j ACCEPT", p, r.ToIP, r.ToPort))
        run(fmt.Sprintf("iptables -I FORWARD -p %s -s %s --sport %s -j ACCEPT", p, r.ToIP, r.ToPort))
    }
}

func removeRule(r Rule) {
    out, _ := exec.Command("iptables-save").Output()
    for _, l := range strings.Split(string(out), "\n") {
        if strings.Contains(l, "gofw-"+r.ID) {
            dl := strings.Replace(l, "-A", "-D", 1)
            run("iptables -t nat " + dl)
        }
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

func main() {
    var port int
    flag.IntVar(&port, "port", 2020, "Port for admin panel")
    flag.Parse()

    abs, _ := filepath.Abs(rulesFile)
    rulesFile = abs
    loadRules()
    for _, r := range rules { if r.Active { applyRule(r) } }

    mux := http.NewServeMux()
    mux.Handle("/", http.FileServer(http.Dir("public")))

    mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock(); defer mu.Unlock()
        if r.Method == "GET" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(rules)
            return
        }
        if r.Method == "POST" {
            var in Rule
            json.NewDecoder(r.Body).Decode(&in)
            if in.FromPort == "" || in.ToIP == "" || in.ToPort == "" { http.Error(w, "missing", 400); return }
            in.ID = fmt.Sprintf("%d", time.Now().UnixNano())
            in.TimeAdded = time.Now()
            in.Active = true
            rules = append(rules, in)
            applyRule(in)
            saveRules()
            json.NewEncoder(w).Encode(in)
            return
        }
        http.Error(w, "Method not allowed", 405)
    })

    mux.HandleFunc("/api/rules/", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock(); defer mu.Unlock()
        id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
        idx := -1
        for i, x := range rules { if x.ID == id { idx = i } }
        if idx == -1 { http.Error(w, "not found", 404); return }
        if r.Method == "DELETE" {
            removeRule(rules[idx])
            rules = append(rules[:idx], rules[idx+1:]...)
            saveRules()
            w.WriteHeader(204)
            return
        }
        if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/toggle") {
            rules[idx].Active = !rules[idx].Active
            if rules[idx].Active { applyRule(rules[idx]) } else { removeRule(rules[idx]) }
            saveRules()
            json.NewEncoder(w).Encode(rules[idx])
            return
        }
        http.Error(w, "Method not allowed", 405)
    })

    log.Printf("GoPortPanel đang chạy tại http://0.0.0.0:%d/\n", port)
    http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux)
}
GO

cat > "$APP_DIR/backend/go.mod" <<'GOMOD'
module goportpanel
go 1.22
GOMOD

echo "==> [5] Sinh source code frontend Vue3 (Vite)"
cat > "$APP_DIR/frontend/package.json" <<'PKG'
{
  "name": "goportpanel-ui",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build"
  },
  "dependencies": {
    "vue": "^3.4.0"
  },
  "devDependencies": {
    "vite": "^5.0.0"
  }
}
PKG

cat > "$APP_DIR/frontend/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="vi">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>GoPortPanel - Port Forward Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div id="app"></div>
    <script type="module" src="/src/main.js"></script>
  </body>
</html>
HTML

cat > "$APP_DIR/frontend/src/App.vue" <<'VUE'
<template>
  <div class="container py-5">
    <h1 class="mb-4 text-center">GoPortPanel - Bảng điều khiển Forwarding</h1>
    <div class="card mb-4 shadow-sm">
      <div class="card-body">
        <form @submit.prevent="addRule" class="row g-3">
          <div class="col-md-2">
            <label class="form-label">Giao thức</label>
            <select v-model="newRule.proto" class="form-select">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">TCP+UDP</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label">Cổng nguồn</label>
            <input v-model="newRule.fromPort" type="number" class="form-control" required>
          </div>
          <div class="col-md-3">
            <label class="form-label">IP đích</label>
            <input v-model="newRule.toIp" type="text" class="form-control" required>
          </div>
          <div class="col-md-2">
            <label class="form-label">Cổng đích</label>
            <input v-model="newRule.toPort" type="number" class="form-control" required>
          </div>
          <div class="col-md-2 d-flex align-items-end">
            <button type="submit" class="btn btn-primary w-100">Lưu</button>
          </div>
        </form>
      </div>
    </div>
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title">Danh sách chuyển tiếp</h5>
        <div class="table-responsive">
          <table class="table table-hover align-middle">
            <thead>
              <tr>
                <th>Giao thức</th>
                <th>Cổng VPS</th>
                <th>IP đích</th>
                <th>Cổng đích</th>
                <th>Thời gian</th>
                <th>Trạng thái</th>
                <th>Hành động</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="rule in rules" :key="rule.id">
                <td>{{ rule.proto.toUpperCase() }}</td>
                <td>{{ rule.fromPort }}</td>
                <td>{{ rule.toIp }}</td>
                <td>{{ rule.toPort }}</td>
                <td>{{ formatTime(rule.timeAdded) }}</td>
                <td>
                  <span class="badge" :class="rule.active ? 'bg-success' : 'bg-secondary'">
                    {{ rule.active ? 'Hoạt động' : 'Tạm dừng' }}
                  </span>
                </td>
                <td>
                  <button @click="toggleRule(rule)" class="btn btn-sm" :class="rule.active ? 'btn-warning' : 'btn-success'">
                    {{ rule.active ? 'Tạm dừng' : 'Kích hoạt' }}
                  </button>
                  <button @click="deleteRule(rule)" class="btn btn-sm btn-danger">Xóa</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
const rules = ref([])
const newRule = ref({ proto: 'tcp', fromPort: '', toIp: '', toPort: '' })

const fetchRules = async () => {
  rules.value = await (await fetch('/api/rules')).json()
}
const addRule = async () => {
  await fetch('/api/rules', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(newRule.value)})
  newRule.value = { proto: 'tcp', fromPort: '', toIp: '', toPort: '' }
  fetchRules()
}
const toggleRule = async (rule) => {
  await fetch(`/api/rules/${rule.id}/toggle`, { method: 'POST' })
  fetchRules()
}
const deleteRule = async (rule) => {
  if(confirm('Bạn có chắc xóa rule này?'))
    await fetch(`/api/rules/${rule.id}`, { method: 'DELETE' })
    fetchRules()
}
const formatTime = (t) => new Date(t).toLocaleString('vi')
onMounted(fetchRules)
</script>
VUE

cat > "$APP_DIR/frontend/src/main.js" <<'JS'
import { createApp } from 'vue'
import App from './App.vue'
createApp(App).mount('#app')
JS

cat > "$APP_DIR/frontend/vite.config.js" <<'VITE'
export default {
  root: '.',
  base: '/',
  build: { outDir: 'dist', emptyOutDir: true }
}
VITE

echo "==> [6] Build backend Go"
cd "$APP_DIR/backend"
go mod tidy
go build -o portpanel main.go

echo "==> [7] Build frontend Vue3"
cd "$APP_DIR/frontend"
npm install
npm run build
rm -rf "$APP_DIR/backend/public"
cp -r dist "$APP_DIR/backend/public"

echo "==> [8] Tạo systemd service"
cat > /etc/systemd/system/goportpanel.service <<EOF
[Unit]
Description=Go Port Forward Panel
After=network.target

[Service]
Environment=PANEL_PORT=$PANEL_PORT
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/backend/portpanel --port \$PANEL_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now goportpanel.service

echo "==> [9] Bật IP forwarding & mở firewall"
sysctl -w net.ipv4.ip_forward=1
iptables -P FORWARD ACCEPT
iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT
iptables-save > /etc/iptables/rules.v4

IP=$(curl -s4 https://api.ipify.org)
echo "==> HOÀN TẤT! Truy cập Panel: http://$IP:$PANEL_PORT/"
