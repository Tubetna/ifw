#!/usr/bin/env bash
set -euo pipefail

PANEL_PORT="${1:-2020}"
APP_DIR="/opt/ifw"
GO_VERSION="1.22.4"
export DEBIAN_FRONTEND=noninteractive

echo "==> [0] Sinh mã backend Go tối ưu forwarding"
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

func applyRule(r Rule) {
    for _, p := range protoMap(r.Proto) {
        removeRule(r)
        run(fmt.Sprintf("iptables -t nat -I PREROUTING -p %s --dport %s -j DNAT --to-destination %s:%s -m comment --comment gofw-%s", p, r.FromPort, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -t nat -I POSTROUTING -p %s -d %s --dport %s -j MASQUERADE -m comment --comment gofw-%s", p, r.ToIP, r.ToPort, r.ID))
        run(fmt.Sprintf("iptables -I FORWARD -p %s -d %s --dport %s -j ACCEPT", p, r.ToIP, r.ToPort))
        run(fmt.Sprintf("iptables -I FORWARD -p %s -s %s --sport %s -j ACCEPT", p, r.ToIP, r.ToPort))
    }
}

func removeRule(r Rule) {
    for _, table := range []string{"nat", "filter"} {
        out, _ := exec.Command("iptables-save", "-t", table).Output()
        for _, l := range strings.Split(string(out), "\n") {
            if strings.Contains(l, "gofw-"+r.ID) {
                line := l
                if strings.HasPrefix(line, "-A") {
                    line = strings.Replace(line, "-A", "-D", 1)
                }
                run(fmt.Sprintf("iptables -t %s %s", table, line))
            }
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
            if err := json.Unmarshal(body, &in); err != nil {
                http.Error(w, "invalid json", 400)
                return
            }
            if in.FromPort == "" || in.ToIP == "" || in.ToPort == "" {
                http.Error(w, "missing", 400)
                return
            }
            for _, x := range rules {
                if x.FromPort == in.FromPort && x.Proto == in.Proto && x.Active {
                    http.Error(w, "Port này đã được forward!", 409)
                    return
                }
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
        if strings.HasSuffix(id, "/toggle") {
            id = strings.TrimSuffix(id, "/toggle")
        }
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
        if r.Method == "PUT" {
            var in Rule
            body, _ := io.ReadAll(r.Body)
            if err := json.Unmarshal(body, &in); err != nil {
                http.Error(w, "invalid json", 400)
                return
            }
            for i, x := range rules {
                if i != idx && x.FromPort == in.FromPort && x.Proto == in.Proto && x.Active {
                    http.Error(w, "Port này đã được forward!", 409)
                    return
                }
            }
            rules[idx].Proto = in.Proto
            rules[idx].FromPort = in.FromPort
            rules[idx].ToIP = in.ToIP
            rules[idx].ToPort = in.ToPort
            if rules[idx].Active { applyRule(rules[idx]) }
            saveRules()
            json.NewEncoder(w).Encode(rules[idx])
            return
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

echo "==> [1] Frontend Vue3 đẹp, hỗ trợ sửa rule, cảnh báo port trùng"
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
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Montserrat:wght@600;900&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body {
        font-family: 'Roboto', Arial, sans-serif;
        background: linear-gradient(135deg, #eaf6ff 0%, #f5f7fa 100%);
        min-height: 100vh;
      }
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
  <div class="container py-5" style="max-width: 950px;">
    <div class="text-center mb-5">
      <h1 class="fw-bold" style="font-family:'Montserrat',sans-serif;letter-spacing:1.5px;font-size:2.7rem;color:#2c72e8;text-shadow:0 4px 18px #a8c7fa;">
        IFW Forwarding Panel
      </h1>
      <div class="small text-muted mt-2" style="font-size:1.07rem;letter-spacing:0.5px;">
        Bảng điều khiển chuyển tiếp Port cho VPS
      </div>
    </div>
    <div class="card shadow-lg border-0 rounded-4 mb-5" style="background:rgba(255,255,255,0.98);">
      <div class="card-body p-4">
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
            <input v-model="newRule.toIp" type="text" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-2">
            <label class="form-label fw-semibold">Cổng đích</label>
            <input v-model="newRule.toPort" type="number" min="1" max="65535" class="form-control rounded-3 border-1 shadow-sm" required>
          </div>
          <div class="col-md-2 d-grid">
            <button type="submit" class="btn btn-primary rounded-3 shadow fw-bold" style="font-size:1.13rem;">
              <i class="bi bi-plus-circle"></i> Lưu Rule
            </button>
          </div>
        </form>
        <div v-if="error" class="alert alert-danger mt-3 py-2 px-3 rounded-3 shadow-sm" role="alert">{{ error }}</div>
      </div>
    </div>
    <div class="card shadow-lg border-0 rounded-4" style="background:rgba(255,255,255,0.97);">
      <div class="card-body p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h5 class="card-title fw-bold mb-0" style="font-size:1.18rem;">Danh sách Port Forwarding</h5>
          <button class="btn btn-outline-primary btn-sm px-3 rounded-pill shadow-sm" @click="fetchRules">
            <i class="bi bi-arrow-clockwise"></i> Làm mới
          </button>
        </div>
        <div class="table-responsive">
          <table class="table align-middle table-hover mb-0" style="font-size:1.08rem;">
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
              <tr v-for="rule in rules" :key="rule.id" :class="{'table-warning':!rule.active}">
                <td>
                  <span class="badge bg-primary bg-gradient rounded-pill px-3 shadow-sm" style="font-size:1em;">
                    {{ rule.proto.toUpperCase() === 'BOTH' ? 'BOTH' : rule.proto.toUpperCase() }}
                  </span>
                </td>
                <td class="fw-semibold">{{ rule.fromPort }}</td>
                <td class="fw-semibold">{{ rule.toIp }}</td>
                <td class="fw-semibold">{{ rule.toPort }}</td>
                <td>{{ formatTime(rule.timeAdded) }}</td>
                <td>
                  <span class="badge rounded-pill px-3" :class="rule.active ? 'bg-success' : 'bg-secondary'">
                    {{ rule.active ? 'Hoạt động' : 'Tạm dừng' }}
                  </span>
                </td>
                <td>
                  <button @click="toggleRule(rule)" class="btn btn-sm me-2 shadow-sm"
                          :class="rule.active ? 'btn-outline-warning' : 'btn-outline-success'">
                    <i :class="rule.active ? 'bi bi-pause-fill' : 'bi bi-play-fill'"></i>
                  </button>
                  <button @click="editRule(rule)" class="btn btn-sm btn-outline-primary shadow-sm me-2">
                    <i class="bi bi-pencil-square"></i>
                  </button>
                  <button @click="deleteRule(rule)" class="btn btn-sm btn-outline-danger shadow-sm">
                    <i class="bi bi-trash"></i>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <div class="text-center mt-4 small text-secondary">
      <span style="letter-spacing:0.2px">© 2025 IFW Panel - Tuỳ chỉnh &amp; tối ưu bởi <b>Tubetna</b></span>
    </div>

    <!-- Modal Edit -->
    <div v-if="editRuleData" class="modal d-block" tabindex="-1" style="background:#0007;">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content p-3">
          <div class="modal-header">
            <h5 class="modal-title">Sửa Rule</h5>
            <button type="button" class="btn-close" @click="editRuleData=null"></button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="saveEditRule">
              <div class="mb-2">
                <label class="form-label">Giao thức</label>
                <select v-model="editRuleData.proto" class="form-select">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="both">TCP+UDP</option>
                </select>
              </div>
              <div class="mb-2">
                <label class="form-label">Cổng nguồn</label>
                <input v-model="editRuleData.fromPort" type="number" class="form-control" required min="1" max="65535">
              </div>
              <div class="mb-2">
                <label class="form-label">IP đích</label>
                <input v-model="editRuleData.toIp" type="text" class="form-control" required>
              </div>
              <div class="mb-2">
                <label class="form-label">Cổng đích</label>
                <input v-model="editRuleData.toPort" type="number" class="form-control" required min="1" max="65535">
              </div>
              <div class="modal-footer">
                <button type="submit" class="btn btn-primary">Lưu</button>
                <button type="button" class="btn btn-secondary" @click="editRuleData=null">Đóng</button>
              </div>
            </form>
          </div>
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
const editRuleData = ref(null)

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
  const postData = {
    proto: newRule.value.proto,
    fromPort: String(newRule.value.fromPort),
    toIp: newRule.value.toIp,
    toPort: String(newRule.value.toPort)
  }
  try {
    const response = await fetch('/api/rules', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(postData)
    })
    if (response.status === 409) {
      error.value = "Port này đã được forward!"
      return
    }
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
const editRule = (rule) => {
  editRuleData.value = { ...rule }
}
const saveEditRule = async () => {
  error.value = ""
  if (!editRuleData.value.fromPort || !editRuleData.value.toIp || !editRuleData.value.toPort) {
    error.value = "Vui lòng nhập đầy đủ thông tin!"
    return
  }
  if (isNaN(+editRuleData.value.fromPort) || +editRuleData.value.fromPort < 1 || +editRuleData.value.fromPort > 65535) {
    error.value = "Cổng nguồn phải là số từ 1 đến 65535!"
    return
  }
  if (isNaN(+editRuleData.value.toPort) || +editRuleData.value.toPort < 1 || +editRuleData.value.toPort > 65535) {
    error.value = "Cổng đích phải là số từ 1 đến 65535!"
    return
  }
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(editRuleData.value.toIp)) {
    error.value = "IP đích không hợp lệ!"
    return
  }
  const body = {
    proto: editRuleData.value.proto,
    fromPort: String(editRuleData.value.fromPort),
    toIp: editRuleData.value.toIp,
    toPort: String(editRuleData.value.toPort)
  }
  try {
    const response = await fetch(`/api/rules/${editRuleData.value.id}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    })
    if (response.status === 409) {
      error.value = "Port này đã được forward!"
      return
    }
    if (!response.ok) {
      error.value = "Không thể cập nhật rule!"
      return
    }
    editRuleData.value = null
    fetchRules()
  } catch (e) {
    error.value = "Lỗi kết nối server!"
  }
}
const formatTime = (t) => t ? new Date(t).toLocaleString('vi') : ''
onMounted(fetchRules)
</script>

<style>
@import "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css";
body {
  background: linear-gradient(135deg, #eaf6ff 0%, #f5f7fa 100%);
  min-height: 100vh;
}
.card {
  border-radius: 1.2rem !important;
  box-shadow: 0 8px 28px rgba(60,130,255,0.07), 0 1.5px 5px rgba(180,200,255,0.09);
}
.badge.bg-primary {
  background: linear-gradient(90deg,#3a89ff 0%,#38e2f1 100%) !important;
  color: #fff;
}
.table th, .table td { vertical-align: middle; }
.btn {
  font-size: 1.05rem;
}
.btn:focus, .form-control:focus, .form-select:focus { box-shadow: 0 0 0 0.18rem #8bcaff41 !important; border-color: #7bb7f7 !important; }
input[type=number]::-webkit-inner-spin-button,
input[type=number]::-webkit-outer-spin-button { opacity: 0.6 }
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

echo "==> [2] Cài Go, Node, iptables-persistent, tối ưu kernel/net"
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
mkdir -p "$APP_DIR/backend/public"
cp -r dist/* "$APP_DIR/backend/public/"

if [ ! -f "$APP_DIR/backend/rules.json" ]; then
    echo '[]' > "$APP_DIR/backend/rules.json"
    chmod 666 "$APP_DIR/backend/rules.json"
fi

echo "==> [5] Tối ưu mạng hệ thống forwarding"
cat <<SYSCTL > /etc/sysctl.d/99-portforward-opt.conf
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_mtu_probing=1
net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_max=1048576
SYSCTL
sysctl --system

iptables -P FORWARD ACCEPT
iptables -F FORWARD
iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT || true
iptables-save > /etc/iptables/rules.v4

if command -v ufw >/dev/null 2>&1; then
    ufw disable || true
fi
if systemctl is-active --quiet firewalld; then
    systemctl stop firewalld
    systemctl disable firewalld
fi

echo "==> [6] Tạo systemd service"
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

IP=$(curl -s4 https://api.ipify.org)
echo "==> HOÀN TẤT! Truy cập Panel: http://$IP:$PANEL_PORT/adminsetupfw/"

systemctl restart ifw

echo "==> DONE! Đã tối ưu forwarding quốc tế TCP/UDP"
