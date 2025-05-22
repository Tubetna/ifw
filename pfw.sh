#!/usr/bin/env bash
# setup_portpanel.sh – Tự động cài đặt "Forward Panel" (backend + frontend Vue3)
# Cách sử dụng: sudo ./setup_portpanel.sh [PANEL_PORT]
set -euo pipefail

PANEL_PORT="${1:-9300}"
APP_DIR="/opt/portpanel"
NODE_VERSION="18.x"

echo "==> 0. Bật IP forwarding một cách cố định"
# Kích hoạt forwarding
sysctl -w net.ipv4.ip_forward=1
# Lưu vào sysctl.conf để khởi động lại vẫn giữ
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || \
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

echo "==> 1. Cài curl, iptables-persistent và Node.js $NODE_VERSION"
apt-get update -y
DEBIAN_FRONTEND=noninteractive \
  apt-get install -y curl iptables-persistent

curl -fsSL https://deb.nodesource.com/setup_$NODE_VERSION | bash - 
DEBIAN_FRONTEND=noninteractive \
  apt-get install -y nodejs

echo "==> 2. Tạo thư mục ứng dụng và chuyển vào"
mkdir -p "$APP_DIR/public"
cd "$APP_DIR"

echo "==> 3. Viết file package.json"
cat > package.json <<'PKG'
{
  "name": "portpanel",
  "version": "1.0.0",
  "description": "Bảng điều khiển chuyển tiếp cổng nâng cao",
  "main": "server.js",
  "type": "module",
  "dependencies": {
    "body-parser": "^1.20.2",
    "express": "^4.19.2",
    "uuid": "^9.0.1"
  }
}
PKG

echo "==> 4. Cài đặt npm dependencies (mirror + fallback)"
export NODE_OPTIONS="--dns-result-order=ipv4first"
npm set registry https://registry.npmmirror.com
npm set cache /root/.npm-mirror-cache --global

install_deps(){
  npm install --omit=dev \
    --cache /root/.npm-mirror-cache \
    --prefer-offline \
    --no-audit \
    --no-fund \
    --progress=false
}

echo "- Thử mirror npmmirror.com..."
if install_deps; then
  echo "  ✓ Mirror thành công."
else
  echo "  ✗ Mirror lỗi, chuyển sang registry npmjs.org..."
  npm set registry https://registry.npmjs.org
  install_deps
fi

echo "==> 5. Viết backend Express (server.js)"
cat > server.js <<'SRV'
import express from 'express';
import bodyParser from 'body-parser';
import { v4 as uuid } from 'uuid';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const APP_PORT = process.env.PANEL_PORT||process.argv[2]||8080;
const DATA_FILE = path.resolve('./rules.json');
const app = express();
app.use(bodyParser.json());
app.use('/adminsetupfw', express.static('public'));

function run(cmd) { execSync(cmd,{stdio:'inherit'}); }
function saveV4() { run('iptables-save>/etc/iptables/rules.v4'); }
function protoMap(p){ return (p==='both'||p==='all')?['tcp','udp']:[p]; }

let rules = [];
if (fs.existsSync(DATA_FILE)) {
  rules = JSON.parse(fs.readFileSync(DATA_FILE));
  rules.forEach(r=> {
    if(r.active) {
      protoMap(r.proto).forEach(p=>{
        run('iptables -t nat -A PREROUTING -p '+p+
            ' --dport '+r.fromPort+
            ' -j DNAT --to-destination '+r.toIp+':'+r.toPort+
            ' -m comment --comment fwpanel-'+r.id);
        run('iptables -t nat -A POSTROUTING -p '+p+
            ' -d '+r.toIp+
            ' --dport '+r.toPort+
            ' -j MASQUERADE -m comment --comment fwpanel-'+r.id);
        run('iptables -I FORWARD -p '+p+' -d '+r.toIp+' --dport '+r.toPort+' -j ACCEPT');
        run('iptables -I FORWARD -p '+p+' -s '+r.toIp+' --sport '+r.toPort+' -j ACCEPT');
      });
    }
  });
  saveV4();
}

function persist(){ fs.writeFileSync(DATA_FILE,JSON.stringify(rules,null,2)); }

// LIST
app.get('/api/rules',(_q,res)=>res.json(rules));

// ADD
app.post('/api/rules',(req,res)=>{
  const{proto='tcp',fromPort,toIp,toPort}=req.body;
  if(!fromPort||!toIp||!toPort) return res.status(400).send('missing');
  const id=uuid(),ts=new Date().toISOString();
  const r={id,proto,fromPort,toIp,toPort,timeAdded:ts,active:true};
  rules.push(r);
  protoMap(proto).forEach(p=>{
    run('iptables -t nat -A PREROUTING -p '+p+
        ' --dport '+fromPort+
        ' -j DNAT --to-destination '+toIp+':'+toPort+
        ' -m comment --comment fwpanel-'+id);
    run('iptables -t nat -A POSTROUTING -p '+p+
        ' -d '+toIp+
        ' --dport '+toPort+
        ' -j MASQUERADE -m comment --comment fwpanel-'+id);
    run('iptables -I FORWARD -p '+p+' -d '+toIp+' --dport '+toPort+' -j ACCEPT');
    run('iptables -I FORWARD -p '+p+' -s '+toIp+' --sport '+toPort+' -j ACCEPT');
  });
  saveV4();persist();
  res.json(r);
});

// DELETE
app.delete('/api/rules/:id',(req,res)=>{
  const{id}=req.params;
  execSync('iptables-save').toString().split('\n')
    .filter(l=>l.includes('fwpanel-'+id))
    .forEach(l=>{
      const d=l.replace(/^-A/,'-D');
      run('iptables -t nat '+d);
    });
  run('iptables-save>/etc/iptables/rules.v4');
  rules=rules.filter(r=>r.id!==id);
  persist();
  res.sendStatus(204);
});

// TOGGLE
app.post('/api/rules/:id/toggle',(req,res)=>{
  const{id}=req.params;
  const r=rules.find(x=>x.id===id);
  if(!r) return res.sendStatus(404);
  if(r.active){
    execSync('iptables-save').toString().split('\n')
      .filter(l=>l.includes('fwpanel-'+id))
      .forEach(l=>{
        const d=l.replace(/^-A/,'-D');
        run('iptables -t nat '+d);
      });
    r.active=false;
  } else {
    protoMap(r.proto).forEach(p=>{
      run('iptables -t nat -A PREROUTING -p '+p+
          ' --dport '+r.fromPort+
          ' -j DNAT --to-destination '+r.toIp+':'+r.toPort+
          ' -m comment --comment fwpanel-'+id);
      run('iptables -t nat -A POSTROUTING -p '+p+
          ' -d '+r.toIp+
          ' --dport '+r.toPort+
          ' -j MASQUERADE -m comment --comment fwpanel-'+id);
      run('iptables -I FORWARD -p '+p+' -d '+r.toIp+' --dport '+r.toPort+' -j ACCEPT');
      run('iptables -I FORWARD -p '+p+' -s '+r.toIp+' --sport '+r.toPort+' -j ACCEPT');
    });
    r.active=true;
  }
  saveV4();persist();
  res.json({id,active:r.active});
});

app.listen(APP_PORT,'0.0.0.0',()=>console.log(`Panel: http://0.0.0.0:${APP_PORT}/adminsetupfw`));
SRV

echo "==> 6. Viết frontend Vue.js (public/index.html)"
cat > public/index.html <<'HTML'
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Bảng điều khiển Port-Forward VPS</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/font-awesome/css/font-awesome.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
</head>
<body class="bg-light">
    <div id="app" class="container py-5">
        <h1 class="mb-4 text-center">Bảng điều khiển Port-Forward VPS</h1>
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
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fa fa-save"></i> Lưu
                        </button>
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
                                <th>Cổng IP VPS</th>
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
                                <td>{{ new Date(rule.timeAdded).toLocaleString() }}</td>
                                <td>
                                    <span class="badge" :class="rule.active ? 'bg-success' : 'bg-secondary'">
                                        {{ rule.active ? 'Hoạt động' : 'Tạm dừng' }}
                                    </span>
                                </td>
                                <td>
                                    <button @click="toggleRule(rule)" class="btn btn-sm" :class="rule.active ? 'btn-warning' : 'btn-success'">
                                        <i class="fa" :class="rule.active ? 'fa-pause' : 'fa-play'"></i>
                                        {{ rule.active ? 'Tạm dừng' : 'Kích hoạt' }}
                                    </button>
                                    <button @click="deleteRule(rule)" class="btn btn-sm btn-danger">
                                        <i class="fa fa-trash"></i> Xóa
                                    </button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        new Vue({
            el: '#app',
            data: {
                newRule: {
                    proto: 'tcp',
                    fromPort: '',
                    toIp: '',
                    toPort: ''
                },
                rules: []
            },
            mounted() {
                this.fetchRules();
            },
            methods: {
                async fetchRules() {
                    const response = await fetch('/api/rules');
                    this.rules = await response.json();
                },
                async addRule() {
                    const response = await fetch('/api/rules', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(this.newRule)
                    });
                    if (response.ok) {
                        this.newRule = { proto: 'tcp', fromPort: '', toIp: '', toPort: '' };
                        this.fetchRules();
                    }
                },
                async toggleRule(rule) {
                    const response = await fetch(`/api/rules/${rule.id}/toggle`, { method: 'POST' });
                    if (response.ok) {
                        this.fetchRules();
                    }
                },
                async deleteRule(rule) {
                    if (confirm('Bạn có chắc chắn muốn xóa quy tắc này không?')) {
                        const response = await fetch(`/api/rules/${rule.id}`, { method: 'DELETE' });
                        if (response.ok) {
                            this.fetchRules();
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
HTML

echo "==> 7. Tạo service systemd"
cat > /etc/systemd/system/portpanel.service <<EOF
[Unit]
Description=Port Forward Panel
After=network.target

[Service]
Environment=PANEL_PORT=$PANEL_PORT
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node /opt/portpanel/server.js \$PANEL_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now portpanel.service

echo "==> 8. Mở firewall & lưu rules"
iptables -P FORWARD ACCEPT
iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT
iptables-save > /etc/iptables/rules.v4

echo "==> Hoàn tất!"
IP=$(curl -s4 https://api.ipify.org)
echo "Truy cập: http://$IP:$PANEL_PORT/adminsetupfw"
