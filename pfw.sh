#!/usr/bin/env bash
set -euo pipefail
PANEL_PORT="${1:-2020}"
APP_DIR="/opt/ifw"
GO_VERSION="1.22.4"
export DEBIAN_FRONTEND=noninteractive

echo "==> [0] Generate backend code"
mkdir -p "$APP_DIR/backend"
cat > "$APP_DIR/backend/main.go" <<'GO'
package main
import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "sync"
    "time"
    "flag"
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
    mux.Handle("/adminsetupfw/assets/", http.StripPrefix("/adminsetupfw/", http.FileServer(http.Dir("public"))))
    mux.Handle("/adminsetupfw/", http.StripPrefix("/adminsetupfw/", http.FileServer(http.Dir("public"))))
    mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
        mu.Lock(); defer mu.Unlock()
        if r.Method == "GET" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(rules)
            return
        }
        if r.Method == "POST" {
            var in Rule
            body, _ := io.ReadAll(r.Body)
            log.Printf("JSON body nhận được: %s\n", body)
            if err := json.Unmarshal(body, &in); err != nil {
                log.Printf("LỖI JSON: %v\n", err)
                http.Error(w, "invalid json", 400)
                return
            }
            log.Printf("ĐÃ PARSE: %+v\n", in)
            if in.FromPort == "" || in.ToIP == "" || in.ToPort == "" {
                log.Printf("LỖI FORM: %+v\n", in)
                http.Error(w, "missing", 400)
                return
            }
            in.ID = fmt.Sprintf("%d", time.Now().UnixNano())
            in.TimeAdded = time.Now()
            in.Active = true
            rules = append(rules, in)
            applyRule(in)
            saveRules()
            w.Header().Set("Content-Type", "application/json")
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
    log.Printf("GoPortPanel đang chạy tại http://0.0.0.0:%d/adminsetupfw/\n", port)
    http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux)
}
GO

cat > "$APP_DIR/backend/go.mod" <<'GOMOD'
module ifw
go 1.22
GOMOD

echo "==> [1] Generate frontend code"
mkdir -p "$APP_DIR/frontend/src"
cat > "$APP_DIR/frontend/package.json" <<'PKG'
{
  "name": "ifw-ui",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build"
  },
  "dependencies": {
    "vue": "^3.4.0"
  },
  "devDependencies": {
    "vite": "^5.0.0",
    "@vitejs/plugin-vue": "^5.0.4"
  }
}
PKG

cat > "$APP_DIR/frontend/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="vi">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IFW PortPanel</title>
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
  <div class="container py-5" style="max-width: 900px;">
    <h1 class="mb-4 text-center fw-bold" style="font-size:2.6rem;letter-spacing:1px;color:#1064ea;">IFW - Bảng điều khiển Forwarding</h1>
    <div class="card mb-4 shadow rounded-4 border-0">
      <div class="card-body">
        <form @submit.prevent="addRule" class="row g-3 align-items-end">
          <div class="col-md-2">
            <label class="form-label fw-semibold">Giao thức</label>
            <select v-model="newRule.proto" class="form-select rounded-3 border-1 shadow-sm">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">TCP+UDP</option>
            </select>
          </div>
          <div class="col-md-3">
            <label class="form-label fw-semibold">Cổng nguồn</label>
            <input v-model="newRule.fromPort" type="number" min="1" max="65535" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-3">
            <label class="form-label fw-semibold">IP đích</label>
            <input v-model="newRule.toIp" type="text" class="form-control rounded-3 border-1 shadow-sm" required pattern="^\\d{1,3}(\\.\\d{1,3}){3}$">
          </div>
          <div class="col-md-2">
            <label class="form-label fw-semibold">Cổng đích</label>
            <input v-model="newRule.toPort" type="number" min="1" max="65535" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-2 d-grid">
            <button type="submit" class="btn btn-primary rounded-3 shadow-sm fw-bold" style="font-size:1.12rem;">Lưu</button>
          </div>
        </form>
        <div v-if="error" class="alert alert-danger mt-3 py-2 px-3 rounded-3" role="alert">{{ error }}</div>
      </div>
    </div>

    <div class="card shadow rounded-4 border-0">
      <div class="card-body">
        <h5 class="card-title fw-bold mb-3" style="font-size:1.18rem;">Danh sách chuyển tiếp</h5>
        <div class="table-responsive">
          <table class="table align-middle table-hover mb-0" style="font-size:1.06rem;">
            <thead class="table-light">
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
              <tr v-if="rules.length === 0">
                <td colspan="7" class="text-center text-muted">Chưa có rule nào</td>
              </tr>
              <tr v-for="rule in rules" :key="rule.id">
                <td><span class="badge bg-gradient text-bg-primary" style="font-size:1em;">{{ rule.proto.toUpperCase() }}</span></td>
                <td>{{ rule.fromPort }}</td>
                <td>{{ rule.toIp }}</td>
                <td>{{ rule.toPort }}</td>
                <td>{{ formatTime(rule.timeAdded) }}</td>
                <td>
                  <span class="badge rounded-pill" :class="rule.active ? 'bg-success' : 'bg-secondary'">
                    {{ rule.active ? 'Hoạt động' : 'Tạm dừng' }}
                  </span>
                </td>
                <td>
                  <button @click="toggleRule(rule)" class="btn btn-sm me-2" :class="rule.active ? 'btn-warning' : 'btn-success'">
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
const error = ref("")
const newRule = ref({ proto: 'tcp', fromPort: '', toIp: '', toPort: '' })
const fetchRules = async () => {
  rules.value = await (await fetch('/api/rules')).json()
}
const addRule = async () => {
  error.value = ""
  if (!newRule.value.fromPort || !newRule.value.toIp || !newRule.value.toPort) {
    error.value = "Vui lòng nhập đầy đủ thông tin!"
    return
  }
  if (isNaN(+newRule.value.fromPort) || +newRule.value.fromPort < 1 || +newRule.value.fromPort > 65535) {
    error.value = "Cổng nguồn phải là số từ 1 đến 65535!"
    return
  }
  if (isNaN(+newRule.value.toPort) || +newRule.value.toPort < 1 || +newRule.value.toPort > 65535) {
    error.value = "Cổng đích phải là số từ 1 đến 65535!"
    return
  }
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(newRule.value.toIp)) {
    error.value = "IP đích không hợp lệ!"
    return
  }
  try {
    const response = await fetch('/api/rules', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(newRule.value)
    })
    if (!response.ok) {
      const msg = await response.text()
      error.value = msg || "Không thể tạo rule"
      return
    }
    newRule.value = { proto: 'tcp', fromPort: '', toIp: '', toPort: '' }
    fetchRules()
  } catch (e) {
    error.value = "Lỗi kết nối server"
  }
}
const toggleRule = async (rule) => {
  error.value = ""
  try {
    const response = await fetch(`/api/rules/${rule.id}/toggle`, { method: 'POST' })
    if (!response.ok) error.value = "Không thể cập nhật trạng thái rule"
    fetchRules()
  } catch (e) { error.value = "Lỗi kết nối server" }
}
const deleteRule = async (rule) => {
  error.value = ""
  if(confirm('Bạn có chắc chắn muốn xóa rule này?')) {
    try {
      const response = await fetch(`/api/rules/${rule.id}`, { method: 'DELETE' })
      if (!response.ok) error.value = "Không thể xóa rule"
      fetchRules()
    } catch (e) { error.value = "Lỗi kết nối server" }
  }
}
const formatTime = (t) => t ? new Date(t).toLocaleString('vi') : ''
onMounted(fetchRules)
</script>

<style>
body {
  background: #f6f8fb !important;
}
.table th, .table td { vertical-align: middle; }
.card { border-radius: 1.2rem !important; }
.badge.bg-gradient {
  background: linear-gradient(90deg,#2697f2,#12b6e7) !important;
  color: #fff;
}
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
export default defineConfig({
  root: '.',
  base: '/adminsetupfw/',
  plugins: [vue()],
  build: { outDir: 'dist', emptyOutDir: true }
})
VITE

echo "==> [2] Cài Go, Node, git, iptables-persistent"
apt-get update -y
apt-get install -y curl git iptables-persistent build-essential
if ! command -v go >/dev/null 2>&1; then
    curl -sL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -xz -C /usr/local
    export PATH="/usr/local/go/bin:$PATH"
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> /root/.profile
fi
if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
fi

cd "$APP_DIR/frontend"
npm install

echo "==> [3] Build backend Go"
cd "$APP_DIR/backend"
go mod tidy
go build -o portpanel main.go

echo "==> [4] Build frontend Vue3"
cd "$APP_DIR/frontend"
npm run build
rm -rf "$APP_DIR/backend/public"
cp -r dist "$APP_DIR/backend/public"

echo "==> [5] Tạo systemd service"
cat > /etc/systemd/system/ifw.service <<EOF
[Unit]
Description=IFW PortPanel
After=network.target
[Service]
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/backend/portpanel --port $PANEL_PORT
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ifw.service

echo "==> [6] Mở forwarding, firewall"
sysctl -w net.ipv4.ip_forward=1
iptables -P FORWARD ACCEPT
iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT || true
iptables-save > /etc/iptables/rules.v4

IP=$(curl -s4 https://api.ipify.org)
echo "==> HOÀN TẤT! Truy cập Panel: http://$IP:$PANEL_PORT/adminsetupfw/"
