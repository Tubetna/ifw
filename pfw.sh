#!/usr/bin/env bash
set -euo pipefail

PANEL_PORT="${1:-2020}"
APP_DIR="/opt/ifw"
GO_VERSION="1.22.4"
export DEBIAN_FRONTEND=noninteractive

if [ "$(id -u)" -ne 0 ]; then echo "Please run as root"; exit 1; fi

echo "==> Prepare dirs"
mkdir -p "$APP_DIR/backend/public" /etc/ipset /etc/iptables

echo "==> Install deps"
apt-get update -y >/dev/null
apt-get install -y curl ca-certificates build-essential iptables iptables-persistent netfilter-persistent ipset conntrack jq >/dev/null

if ! command -v go >/dev/null 2>&1; then
  echo "==> Install Go $GO_VERSION"
  curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -xz -C /usr/local
  export PATH="/usr/local/go/bin:$PATH"
  grep -q '/usr/local/go/bin' /root/.profile || echo 'export PATH="/usr/local/go/bin:$PATH"' >> /root/.profile
fi

echo "==> Load kernel modules"
modprobe ip_set 2>/dev/null || true
modprobe ip_set_hash_ip 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true
modprobe nf_synproxy_core 2>/dev/null || true
modprobe xt_set 2>/dev/null || true

echo "==> Sysctl tune"
cat > /etc/sysctl.d/99-ifw-dnat.conf <<SYSCTL
net.core.somaxconn=8192
net.core.netdev_max_backlog=250000
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.ip_forward=1
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_max_syn_backlog=16384
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=120
net.netfilter.nf_conntrack_tcp_timeout_established=600
SYSCTL
sysctl --system >/dev/null || true

echo "==> Base ipset/iptables"
ipset create gofw_block hash:ip family inet maxelem 200000 -exist
ipset create gofw_white hash:ip family inet maxelem 100000 -exist
iptables -t raw -C PREROUTING -m set --match-set gofw_block src -j DROP 2>/dev/null || \
iptables -t raw -I PREROUTING -m set --match-set gofw_block src -j DROP
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT || true
iptables-save > /etc/iptables/rules.v4 || true
ipset save > /etc/ipset/rules.v4 || true
netfilter-persistent save || true

echo "==> Backend (Go)"
cat > "$APP_DIR/backend/go.mod" <<'GOMOD'
module ifw
go 1.22
GOMOD

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
	"sort"
	"strconv"
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

func defaultConfig() Config { return Config{DDOSDefense:true, TcpSynPerIp:150, TcpSynBurst:300, TcpConnPerIp:250, UdpPpsPerIp:8000, UdpBurst:12000} }
func getenvInt(k string, def int) int { if v:=os.Getenv(k); v!="" { var x int; if _,e:=fmt.Sscanf(v,"%d",&x); e==nil && x>0 { return x } } ; return def }
func run(cmd string) error { log.Println("[CMD]",cmd); a:=strings.Fields(cmd); out,err:=exec.Command(a[0],a[1:]...).CombinedOutput(); if err!=nil { log.Printf("[ERR] %s => %s",cmd,out) } ; return err }
func protoMap(p string) []string { switch strings.ToLower(p){ case "both","all": return []string{"tcp","udp"} ; default: return []string{strings.ToLower(p)} } }

func removeRuleSingle(r Rule, proto string) {
	for _, table := range []string{"raw","mangle","nat","filter"} {
		out, _ := exec.Command("iptables-save", "-t", table).Output()
		for _, l := range strings.Split(string(out), "\n") {
			if (strings.Contains(l,"gofw-"+r.ID) || strings.Contains(l,"gofwdef-"+r.ID) || strings.Contains(l,"gofwwhite-"+r.ID) || strings.Contains(l,"gofwseen-"+r.ID)) &&
				(strings.Contains(l, proto) || proto=="both") {
				line := l; if strings.HasPrefix(line,"-A") { line = strings.Replace(line,"-A","-D",1) }
				run(fmt.Sprintf("iptables -t %s %s", table, line))
			}
		}
	}
}
func applyWhitelistBypass(r Rule) {
	id := r.ID
	for _, p := range protoMap(r.Proto) {
		run(fmt.Sprintf(`iptables -I FORWARD -p %s -m set --match-set gofw_white src -d %s --dport %s -m comment --comment gofwwhite-%s -j ACCEPT`, p,r.ToIP,r.ToPort,id))
	}
}
func applyDefense(r Rule) {
	if !cfg.DDOSDefense { return }
	id := r.ID
	for _, p := range protoMap(r.Proto) {
		if p=="tcp" {
			// pre-DNAT: match FromPort
			run(fmt.Sprintf(`iptables -t raw -I PREROUTING -p tcp --dport %s --syn -m comment --comment gofwdef-%s -j CT --notrack`, r.FromPort, id))
			run(fmt.Sprintf(`iptables -t mangle -I PREROUTING -p tcp --dport %s --syn -m comment --comment gofwdef-%s -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460`, r.FromPort, id))
			// post-DNAT limits
			run(fmt.Sprintf(`iptables -I FORWARD -m conntrack --ctstate INVALID -d %s --dport %s -m comment --comment gofwdef-%s -j DROP`, r.ToIP, r.ToPort, id))
			run(fmt.Sprintf(`iptables -I FORWARD -p tcp -d %s --dport %s --syn -m hashlimit --hashlimit-above %d/second --hashlimit-burst %d --hashlimit-mode srcip --hashlimit-name syn-%s -m comment --comment gofwdef-%s -j DROP`,
				r.ToIP, r.ToPort, cfg.TcpSynPerIp, cfg.TcpSynBurst, id, id))
			run(fmt.Sprintf(`iptables -I FORWARD -p tcp -d %s --dport %s -m connlimit --connlimit-above %d --connlimit-mask 32 -m comment --comment gofwdef-%s -j DROP`,
				r.ToIP, r.ToPort, cfg.TcpConnPerIp, id))
		}
		if p=="udp" {
			run(fmt.Sprintf(`iptables -I FORWARD -p udp -d %s --dport %s -m conntrack --ctstate NEW -m hashlimit --hashlimit-above %d/second --hashlimit-burst %d --hashlimit-mode srcip --hashlimit-name udpf-%s -m comment --comment gofwdef-%s -j DROP`,
				r.ToIP, r.ToPort, cfg.UdpPpsPerIp, cfg.UdpBurst, id, id))
		}
	}
	run("iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
}
func applyDNAT(r Rule) {
	id := r.ID
	for _, p := range protoMap(r.Proto) {
		run(fmt.Sprintf("iptables -t nat -I PREROUTING -p %s --dport %s -m comment --comment gofw-%s -j DNAT --to-destination %s:%s", p, r.FromPort, id, r.ToIP, r.ToPort))
		run(fmt.Sprintf("iptables -t nat -I POSTROUTING -p %s -d %s --dport %s -m comment --comment gofw-%s -j MASQUERADE", p, r.ToIP, r.ToPort, id))
		run(fmt.Sprintf("iptables -I FORWARD -p %s -d %s --dport %s -m comment --comment gofw-%s -j ACCEPT", p, r.ToIP, r.ToPort, id))
		run(fmt.Sprintf("iptables -I FORWARD -p %s -s %s --sport %s -m comment --comment gofw-%s -j ACCEPT", p, r.ToIP, r.ToPort, id))
	}
}
func createPerRuleSets(r Rule) {
	run(fmt.Sprintf("ipset create gofw_syn_%s  hash:ip timeout 60 counters -exist", r.ID))
	run(fmt.Sprintf("ipset create gofw_seen_%s hash:ip timeout 180 counters -exist", r.ID))
}
func applySeenTracking(r Rule) {
	createPerRuleSets(r)
	id := r.ID
	for _, p := range protoMap(r.Proto) {
		// pre-DNAT: track SYN/NEW theo FromPort
		if p=="tcp" {
			run(fmt.Sprintf(`iptables -t mangle -I PREROUTING -p tcp --dport %s --syn -m comment --comment gofwseen-%s -j SET --add-set gofw_syn_%s src`, r.FromPort, id, id))
		}
		if p=="udp" {
			run(fmt.Sprintf(`iptables -t mangle -I PREROUTING -p udp --dport %s -m conntrack --ctstate NEW -m comment --comment gofwseen-%s -j SET --add-set gofw_syn_%s src`, r.FromPort, id, id))
		}
		// post-DNAT: flow thật
		run(fmt.Sprintf(`iptables -I FORWARD -p %s -d %s --dport %s -m comment --comment gofwseen-%s -j SET --add-set gofw_seen_%s src`, p, r.ToIP, r.ToPort, id, id))
	}
}
func applyRule(r Rule){ applyWhitelistBypass(r); applyDefense(r); applyDNAT(r); applySeenTracking(r) }

func removeRule(r Rule){
	removeRuleSingle(r,"both")
	_ = run(fmt.Sprintf("ipset destroy gofw_syn_%s 2>/dev/null || ipset flush gofw_syn_%s || true", r.ID, r.ID))
	_ = run(fmt.Sprintf("ipset destroy gofw_seen_%s 2>/dev/null || ipset flush gofw_seen_%s || true", r.ID, r.ID))
}

func saveRules(){ f,_:=os.Create(rulesFile); defer f.Close(); enc:=json.NewEncoder(f); enc.SetIndent("","  "); _=enc.Encode(rules) }
func loadRules(){ f,err:=os.Open(rulesFile); if err!=nil { return }; defer f.Close(); _=json.NewDecoder(f).Decode(&rules) }
func saveConfig() error { f,err:=os.Create(configFile); if err!=nil { return err }; defer f.Close(); enc:=json.NewEncoder(f); enc.SetIndent("","  "); return enc.Encode(cfg) }
func loadConfig(){
	cfg=defaultConfig()
	cfg.TcpSynPerIp=getenvInt("DDOS_TCP_SYN_PER_IP",cfg.TcpSynPerIp)
	cfg.TcpSynBurst=getenvInt("DDOS_TCP_SYN_BURST",cfg.TcpSynBurst)
	cfg.TcpConnPerIp=getenvInt("DDOS_TCP_CONN_PER_IP",cfg.TcpConnPerIp)
	cfg.UdpPpsPerIp=getenvInt("DDOS_UDP_PPS_PER_IP",cfg.UdpPpsPerIp)
	cfg.UdpBurst=getenvInt("DDOS_UDP_BURST",cfg.UdpBurst)
	if os.Getenv("DDOS_DEFENSE")=="0" { cfg.DDOSDefense=false }
	if f,err:=os.Open(configFile); err==nil {
		defer f.Close()
		var c Config
		if json.NewDecoder(f).Decode(&c)==nil {
			if c.TcpSynPerIp>0 { cfg.TcpSynPerIp=c.TcpSynPerIp }
			if c.TcpSynBurst>0 { cfg.TcpSynBurst=c.TcpSynBurst }
			if c.TcpConnPerIp>0 { cfg.TcpConnPerIp=c.TcpConnPerIp }
			if c.UdpPpsPerIp>0 { cfg.UdpPpsPerIp=c.UdpPpsPerIp }
			if c.UdpBurst>0 { cfg.UdpBurst=c.UdpBurst }
			cfg.DDOSDefense=c.DDOSDefense
		}
	}
	_ = saveConfig()
}

type ipCount struct { IP string; Pkts int }
func readIPSetCounts(name string) ([]ipCount, error) {
	out, err := exec.Command("ipset", "list", name, "-o", "save").CombinedOutput()
	if err != nil { return nil, fmt.Errorf("ipset list %s error: %v\n%s", name, err, out) }
	res := []ipCount{}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "add "+name+" ") { continue }
		fields := strings.Fields(strings.TrimPrefix(l, "add "+name+" "))
		if len(fields)==0 { continue }
		ip := fields[0]; pkts := 0
		for i:=1; i<len(fields)-1; i++ {
			if fields[i]=="packets" { if v,err := strconv.Atoi(fields[i+1]); err==nil { pkts=v } }
		}
		if pkts==0 { pkts=1 }
		res = append(res, ipCount{IP:ip,Pkts:pkts})
	}
	return res, nil
}

func main(){
	var port int
	flag.IntVar(&port,"port",2020,"Port for admin panel")
	flag.Parse()
	abs,_ := filepath.Abs(rulesFile); rulesFile = abs
	absC,_ := filepath.Abs(configFile); configFile = absC

	_ = run("ipset create gofw_block hash:ip family inet maxelem 200000 -exist")
	_ = run("ipset create gofw_white hash:ip family inet maxelem 100000 -exist")
	_ = run("iptables -t raw -C PREROUTING -m set --match-set gofw_block src -j DROP 2>/dev/null || iptables -t raw -I PREROUTING -m set --match-set gofw_block src -j DROP")
	_ = run("iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

	loadConfig(); loadRules()
	for _, r := range rules { if r.Active { applyRule(r) } }

	mux := http.NewServeMux()
	mux.Handle("/adminsetupfw/", http.StripPrefix("/adminsetupfw/", http.FileServer(http.Dir("public"))))

	// CRUD rules
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request){
		mu.Lock(); defer mu.Unlock()
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(rules)
		case "POST":
			var in Rule; b,_ := io.ReadAll(r.Body)
			if json.Unmarshal(b,&in)!=nil || in.FromPort=="" || in.ToIP=="" || in.ToPort=="" { http.Error(w,"invalid json",400); return }
			for _, x := range rules { if x.FromPort==in.FromPort && strings.EqualFold(x.Proto,in.Proto) && x.Active { http.Error(w,"Port này đã được forward!",409); return } }
			in.ID = fmt.Sprintf("%d", time.Now().UnixNano())
			in.TimeAdded = time.Now(); in.Active=true
			rules = append(rules,in); applyRule(in); saveRules()
			w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(in)
		default: http.Error(w,"Method not allowed",405)
		}
	})
	mux.HandleFunc("/api/rules/", func(w http.ResponseWriter, r *http.Request){
		mu.Lock(); defer mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path,"/api/rules/")
		if strings.HasSuffix(id,"/toggle"){ id = strings.TrimSuffix(id,"/toggle") }
		idx := -1; for i,x := range rules { if x.ID==id { idx=i; break } }
		if idx==-1 { http.Error(w,"not found",404); return }
		switch {
		case r.Method=="DELETE":
			removeRule(rules[idx]); rules = append(rules[:idx], rules[idx+1:]...); saveRules(); w.WriteHeader(204)
		case r.Method=="POST" && strings.HasSuffix(r.URL.Path,"/toggle"):
			rules[idx].Active = !rules[idx].Active
			if rules[idx].Active { applyRule(rules[idx]) } else { removeRule(rules[idx]) }
			saveRules(); w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(rules[idx])
		case r.Method=="PUT":
			var in Rule; b,_ := io.ReadAll(r.Body)
			if json.Unmarshal(b,&in)!=nil { http.Error(w,"invalid json",400); return }
			for i,x := range rules { if i!=idx && x.FromPort==in.FromPort && strings.EqualFold(x.Proto,in.Proto) && x.Active { http.Error(w,"Port này đã được forward!",409); return } }
			was := rules[idx].Active
			if was { removeRuleSingle(rules[idx],"both") }
			rules[idx].Proto=in.Proto; rules[idx].FromPort=in.FromPort; rules[idx].ToIP=in.ToIP; rules[idx].ToPort=in.ToPort
			if was { applyRule(rules[idx]) }
			saveRules(); w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(rules[idx])
		default: http.Error(w,"Method not allowed",405)
		}
	})

	// block/unblock/list
	type ipReq struct{ IP string `json:"ip"` }
	mux.HandleFunc("/api/block", func(w http.ResponseWriter, r *http.Request){
		if r.Method!="POST" { http.Error(w,"Method not allowed",405); return }
		var in ipReq; b,_ := io.ReadAll(r.Body)
		if json.Unmarshal(b,&in)!=nil || in.IP=="" { http.Error(w,"invalid json/ip",400); return }
		if run(fmt.Sprintf("ipset add gofw_block %s -exist", in.IP))!=nil { http.Error(w,"failed",500); return }
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/unblock", func(w http.ResponseWriter, r *http.Request){
		if r.Method!="POST" { http.Error(w,"Method not allowed",405); return }
		var in ipReq; b,_ := io.ReadAll(r.Body)
		if json.Unmarshal(b,&in)!=nil || in.IP=="" { http.Error(w,"invalid json/ip",400); return }
		if run(fmt.Sprintf("ipset del gofw_block %s", in.IP))!=nil { http.Error(w,"failed",500); return }
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/blocked", func(w http.ResponseWriter, r *http.Request){
		out,err := exec.Command("ipset","list","gofw_block","-o","save").CombinedOutput()
		if err!=nil { http.Error(w,err.Error(),500); return }
		ips := []string{}
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f)==3 && f[0]=="add" && f[1]=="gofw_block" { ips = append(ips, f[2]) }
		}
		w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(map[string]any{"set":"gofw_block","count":len(ips),"ips":ips})
	})
	mux.HandleFunc("/api/whitelist", func(w http.ResponseWriter, r *http.Request){
		if r.Method!="POST" { http.Error(w,"Method not allowed",405); return }
		var in ipReq; b,_ := io.ReadAll(r.Body)
		if json.Unmarshal(b,&in)!=nil || in.IP=="" { http.Error(w,"invalid json/ip",400); return }
		if run(fmt.Sprintf("ipset add gofw_white %s -exist", in.IP))!=nil { http.Error(w,"failed",500); return }
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/unwhitelist", func(w http.ResponseWriter, r *http.Request){
		if r.Method!="POST" { http.Error(w,"Method not allowed",405); return }
		var in ipReq; b,_ := io.ReadAll(r.Body)
		if json.Unmarshal(b,&in)!=nil || in.IP=="" { http.Error(w,"invalid json/ip",400); return }
		if run(fmt.Sprintf("ipset del gofw_white %s", in.IP))!=nil { http.Error(w,"failed",500); return }
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/whitelisted", func(w http.ResponseWriter, r *http.Request){
		out,err := exec.Command("ipset","list","gofw_white","-o","save").CombinedOutput()
		if err!=nil { http.Error(w,err.Error(),500); return }
		ips := []string{}
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f)==3 && f[0]=="add" && f[1]=="gofw_white" { ips = append(ips, f[2]) }
		}
		w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(map[string]any{"set":"gofw_white","count":len(ips),"ips":ips})
	})

	// connections: đọc per-rule ipset
	mux.HandleFunc("/api/connections", func(w http.ResponseWriter, r *http.Request){
		type Conn struct {
			IP string `json:"ip"`
			FromPort string `json:"fromPort"`
			ToIP string `json:"toIp"`
			ToPort string `json:"toPort"`
			RuleID string `json:"rule"`
			Phase string `json:"phase"` // EST | SYN
			Count int `json:"count"`
		}
		out := []Conn{}
		mu.Lock(); local := make([]Rule,0,len(rules)); for _,ru := range rules { if ru.Active { local=append(local,ru) } }; mu.Unlock()

		for _, ru := range local {
			seen, _ := readIPSetCounts("gofw_seen_"+ru.ID)
			for _, e := range seen { out = append(out, Conn{IP:e.IP, FromPort:ru.FromPort, ToIP:ru.ToIP, ToPort:ru.ToPort, RuleID:ru.ID, Phase:"EST", Count:e.Pkts}) }
			syns, _ := readIPSetCounts("gofw_syn_"+ru.ID)
			for _, e := range syns { out = append(out, Conn{IP:e.IP, FromPort:ru.FromPort, ToIP:ru.ToIP, ToPort:ru.ToPort, RuleID:ru.ID, Phase:"SYN", Count:e.Pkts}) }
		}
		w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(out)
	})

	// suspected: top IP theo SYN (tổng mọi rule)
	mux.HandleFunc("/api/suspected", func(w http.ResponseWriter, r *http.Request){
		type SI struct{ IP string `json:"ip"`; Count int `json:"count"` }
		mp := map[string]int{}
		mu.Lock(); local := make([]Rule,0,len(rules)); for _,ru := range rules { if ru.Active { local=append(local,ru) } }; mu.Unlock()
		for _, ru := range local {
			syns, _ := readIPSetCounts("gofw_syn_"+ru.ID)
			for _, e := range syns { mp[e.IP]+=e.Pkts }
		}
		arr := []SI{}; for ip,c := range mp { arr = append(arr, SI{ip,c}) }
		sort.Slice(arr, func(i,j int)bool{ return arr[i].Count>arr[j].Count })
		if len(arr)>200 { arr = arr[:200] }
		w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(arr)
	})

	// config
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request){
		mu.Lock(); defer mu.Unlock()
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(cfg)
		case "PUT":
			var in Config; b,_ := io.ReadAll(r.Body)
			if json.Unmarshal(b,&in)!=nil { http.Error(w,"invalid json",400); return }
			if in.DDOSDefense {
				if in.TcpSynPerIp<=0 || in.TcpSynBurst<=0 || in.TcpConnPerIp<=0 || in.UdpPpsPerIp<=0 || in.UdpBurst<=0 {
					http.Error(w,"values must be > 0",400); return
				}
			}
			prev := cfg.DDOSDefense; cfg = in
			if err := saveConfig(); err!=nil { http.Error(w,"save failed",500); return }
			if prev || cfg.DDOSDefense {
				for _, r := range rules { if r.Active { removeRuleSingle(r,"both"); applyRule(r) } }
			}
			w.Header().Set("Content-Type","application/json"); _=json.NewEncoder(w).Encode(cfg)
		default: http.Error(w,"Method not allowed",405)
		}
	})

	log.Printf("IFW DNAT Panel http://0.0.0.0:%d/adminsetupfw/\n", port)
	_ = http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux)
}
GO

echo "==> Frontend (Vue CDN, mượt, tối giản)"
cat > "$APP_DIR/backend/public/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IFW DNAT Panel</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
  <style>
    :root{--pri:#3a89ff;--pri2:#38e2f1}
    body{font-family:'Inter',system-ui,Arial,sans-serif;background:radial-gradient(1100px 700px at 10% 0%,#eef5ff 0%,#f7fbff 40%,#ffffff 100%);color:#111827}
    .glass{background:rgba(255,255,255,.92);backdrop-filter:blur(10px);border:1px solid #e6edff;border-radius:22px;box-shadow:0 12px 36px rgba(24,79,176,.08)}
    .hero{letter-spacing:.3px;color:#2056c7;text-shadow:0 8px 26px rgba(45,114,255,.25)}
    .pill{border-radius:999px}
    .grad{background:linear-gradient(90deg,var(--pri),var(--pri2));color:#fff}
    .btn-grad{background:linear-gradient(90deg,var(--pri),var(--pri2));color:#fff;border:0}
    .btn-grad:hover{opacity:.96;color:#fff}
    .muted{color:#6b7280}
    .chip{display:inline-flex;align-items:center;gap:.4rem;padding:.15rem .55rem;border-radius:999px;font-size:.75rem}
  </style>
</head>
<body>
  <div id="app" class="container py-5" style="max-width:1180px">
    <div class="text-center mb-4">
      <h1 class="hero fw-800">IFW DNAT Panel</h1>
      <div class="muted">Kernel DNAT • SYNPROXY • hashlimit/connlimit • raw-drop • Whitelist bypass</div>
    </div>

    <ul class="nav nav-pills justify-content-center gap-2 mb-4">
      <li class="nav-item"><button class="nav-link pill" :class="tab==='rules'?'grad':''" @click="go('rules')"><i class="bi bi-diagram-3"></i> Rules</button></li>
      <li class="nav-item"><button class="nav-link pill" :class="tab==='lists'?'grad':''" @click="go('lists')"><i class="bi bi-activity"></i> Danh sách IP</button></li>
      <li class="nav-item"><button class="nav-link pill" :class="tab==='blocked'?'grad':''" @click="go('blocked')"><i class="bi bi-shield-x"></i> Blocklist</button></li>
      <li class="nav-item"><button class="nav-link pill" :class="tab==='whitelist'?'grad':''" @click="go('whitelist')"><i class="bi bi-shield-check"></i> Whitelist</button></li>
      <li class="nav-item"><button class="nav-link pill" :class="tab==='rate'?'grad':''" @click="go('rate')"><i class="bi bi-speedometer2"></i> Rate Config</button></li>
    </ul>

    <div v-if="toast" class="alert" :class="toast.cls">{{ toast.msg }}</div>

    <!-- Rules create -->
    <div v-show="tab==='rules'" class="glass p-4 mb-4">
      <form @submit.prevent="createRule" class="row g-3 align-items-end">
        <div class="col-md-2">
          <label class="form-label">Giao thức</label>
          <select v-model="form.proto" class="form-select pill">
            <option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option>
          </select>
        </div>
        <div class="col-md-3">
          <label class="form-label">Cổng VPS (From)</label>
          <input v-model="form.fromPort" type="number" min="1" max="65535" class="form-control pill" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">IP đích</label>
          <input v-model="form.toIp" type="text" class="form-control pill" required>
        </div>
        <div class="col-md-2">
          <label class="form-label">Cổng đích</label>
          <input v-model="form.toPort" type="number" min="1" max="65535" class="form-control pill" required>
        </div>
        <div class="col-md-2 d-grid">
          <button class="btn btn-grad pill fw-semibold"><i class="bi bi-plus-circle"></i> Tạo</button>
        </div>
      </form>
    </div>

    <!-- Rules list -->
    <div v-show="tab==='rules'" class="glass p-4">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="mb-0">Danh sách DNAT</h5>
        <button class="btn btn-outline-primary pill btn-sm" @click="fetchRules"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
      </div>
      <div class="table-responsive">
        <table class="table align-middle">
          <thead class="table-light"><tr>
            <th>Proto</th><th>FromPort</th><th>Đích</th><th>Thêm lúc</th><th>Trạng thái</th><th>Hành động</th>
          </tr></thead>
          <tbody>
            <tr v-if="rules.length===0"><td colspan="6" class="text-center muted">Chưa có rule</td></tr>
            <tr v-for="r in rules" :key="r.id" :class="{'table-warning':!r.active}">
              <td><span class="chip bg-primary text-white">{{ r.proto.toUpperCase()==='BOTH'?'BOTH':r.proto.toUpperCase() }}</span></td>
              <td class="fw-semibold">{{ r.fromPort }}</td>
              <td class="fw-semibold">{{ r.toIp }}:{{ r.toPort }}</td>
              <td>{{ fmt(r.timeAdded) }}</td>
              <td><span class="chip" :class="r.active?'bg-success text-white':'bg-secondary text-white'">{{ r.active?'Active':'Paused' }}</span></td>
              <td class="d-flex gap-2">
                <button @click="toggleRule(r)" class="btn btn-sm" :class="r.active?'btn-outline-warning':'btn-outline-success'"><i :class="r.active?'bi bi-pause':'bi bi-play'"></i></button>
                <button @click="edit(r)" class="btn btn-sm btn-outline-primary"><i class="bi bi-pencil-square"></i></button>
                <button @click="del(r)" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Lists -->
    <div v-show="tab==='lists'" class="glass p-4">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="mb-0">Danh sách IP realtime</h5>
        <div class="d-flex gap-2">
          <button class="btn btn-outline-danger btn-sm pill" @click="blockAll"><i class="bi bi-shield-slash"></i> Block All</button>
          <button class="btn btn-outline-secondary btn-sm pill" @click="loadLists"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
        </div>
      </div>
      <div class="row g-3">
        <div class="col-lg-6">
          <h6>Đã qua SYNPROXY (EST)</h6>
          <div v-if="est.length===0" class="muted">Chưa có flow thực sự</div>
          <div v-for="c in est" :key="'e-'+c.rule+'-'+c.ip" class="py-2 border-bottom d-flex justify-content-between">
            <div>
              <div class="fw-semibold">{{ c.ip }} → {{ c.toIp }}:{{ c.toPort }}</div>
              <div class="muted small">Rule: {{ c.rule }} • Packets: {{ c.count }} • FromPort: {{ c.fromPort }}</div>
            </div>
            <div class="btn-group">
              <button class="btn btn-sm btn-outline-danger" @click="blockIP(c.ip)">Block</button>
              <button class="btn btn-sm btn-outline-success" @click="whiteIP(c.ip)">Whitelist</button>
            </div>
          </div>
        </div>
        <div class="col-lg-6">
          <h6>SYN hits (pre-handshake)</h6>
          <div v-if="syn.length===0" class="muted">Không có IP nghi ngờ</div>
          <div v-for="s in syn" :key="'s-'+s.rule+'-'+s.ip" class="py-2 border-bottom d-flex justify-content-between">
            <div>
              <div class="fw-semibold">{{ s.ip }} → FromPort {{ s.fromPort }}</div>
              <div class="muted small">Rule: {{ s.rule }} • SYN pkts: {{ s.count }} • To {{ s.toIp }}:{{ s.toPort }}</div>
            </div>
            <div class="btn-group">
              <button class="btn btn-sm btn-outline-danger" @click="blockIP(s.ip)">Block</button>
              <button class="btn btn-sm btn-outline-success" @click="whiteIP(s.ip)">Whitelist</button>
            </div>
          </div>
        </div>

        <div class="col-12">
          <h6 class="mt-2">Blocklist / Whitelist hiện tại</h6>
          <div class="row g-2">
            <div class="col-md-6"><div class="p-3 border rounded-3">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <b>Blocked</b>
                <div class="input-group input-group-sm" style="max-width:360px">
                  <input v-model="blkIp" class="form-control pill" placeholder="IPv4">
                  <button class="btn btn-outline-danger pill" @click="blockIP(blkIp)">Block</button>
                </div>
              </div>
              <div class="small muted" v-if="blocked.length===0">Trống</div>
              <div class="d-flex gap-2 flex-wrap">
                <span v-for="ip in blocked" :key="'b-'+ip" class="chip bg-danger text-white">{{ ip }}
                  <button class="btn btn-sm btn-light ms-1 py-0 px-1" @click="unblockIP(ip)"><i class="bi bi-x"></i></button>
                </span>
              </div>
            </div></div>
            <div class="col-md-6"><div class="p-3 border rounded-3">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <b>Whitelist</b>
                <div class="input-group input-group-sm" style="max-width:360px">
                  <input v-model="wIp" class="form-control pill" placeholder="IPv4">
                  <button class="btn btn-outline-success pill" @click="whiteIP(wIp)">Add</button>
                </div>
              </div>
              <div class="small muted" v-if="white.length===0">Trống</div>
              <div class="d-flex gap-2 flex-wrap">
                <span v-for="ip in white" :key="'w-'+ip" class="chip bg-success text-white">{{ ip }}
                  <button class="btn btn-sm btn-light ms-1 py-0 px-1" @click="unwhiteIP(ip)"><i class="bi bi-x"></i></button>
                </span>
              </div>
            </div></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Rate -->
    <div v-show="tab==='rate'" class="glass p-4">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="mb-0">Cấu hình chống DDoS</h5>
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" v-model="cfg.ddosDefense" id="sw"><label class="form-check-label" for="sw">Bật chống DDoS</label>
        </div>
      </div>
      <div class="row g-3">
        <div class="col-md-4"><label class="form-label">TCP SYN/IP/s</label><input type="number" min="10" v-model.number="cfg.tcpSynPerIp" class="form-control pill" :disabled="!cfg.ddosDefense"></div>
        <div class="col-md-4"><label class="form-label">TCP SYN Burst</label><input type="number" min="10" v-model.number="cfg.tcpSynBurst" class="form-control pill" :disabled="!cfg.ddosDefense"></div>
        <div class="col-md-4"><label class="form-label">TCP connections/IP</label><input type="number" min="10" v-model.number="cfg.tcpConnPerIp" class="form-control pill" :disabled="!cfg.ddosDefense"></div>
        <div class="col-md-6"><label class="form-label">UDP PPS NEW/IP</label><input type="number" min="100" v-model.number="cfg.udpPpsPerIp" class="form-control pill" :disabled="!cfg.ddosDefense"></div>
        <div class="col-md-6"><label class="form-label">UDP Burst</label><input type="number" min="100" v-model.number="cfg.udpBurst" class="form-control pill" :disabled="!cfg.ddosDefense"></div>
      </div>
      <div class="text-end mt-3"><button class="btn btn-grad pill" @click="saveCfg"><i class="bi bi-save"></i> Lưu & Áp dụng</button></div>
      <div class="small muted mt-2">Whitelist được bỏ qua mọi hạn chế.</div>
    </div>

    <!-- Modal edit -->
    <div v-if="editing" class="position-fixed top-0 start-0 w-100 h-100" style="background:#0006">
      <div class="d-flex align-items-center justify-content-center h-100">
        <div class="glass p-3" style="min-width:360px">
          <div class="d-flex justify-content-between align-items-center mb-2">
            <h5 class="mb-0">Sửa Rule</h5>
            <button class="btn btn-sm btn-outline-secondary" @click="editing=null"><i class="bi bi-x-lg"></i></button>
          </div>
          <div class="mb-2"><label class="form-label">Proto</label>
            <select v-model="editing.proto" class="form-select pill"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP+UDP</option></select>
          </div>
          <div class="mb-2"><label class="form-label">FromPort</label><input v-model="editing.fromPort" type="number" min="1" max="65535" class="form-control pill"></div>
          <div class="mb-2"><label class="form-label">IP đích</label><input v-model="editing.toIp" type="text" class="form-control pill"></div>
          <div class="mb-3"><label class="form-label">Cổng đích</label><input v-model="editing.toPort" type="number" min="1" max="65535" class="form-control pill"></div>
          <div class="text-end"><button class="btn btn-grad pill" @click="saveEdit">Lưu</button></div>
        </div>
      </div>
    </div>

    <div class="text-center mt-4 muted small">© 2025 IFW • DNAT trong kernel — Forward mượt, chống sập port</div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/vue@3.4.38/dist/vue.global.prod.js"></script>
  <script>
    const { createApp, ref, onMounted } = Vue
    createApp({
      setup(){
        const tab = ref('lists'), rules = ref([]), toast = ref(null), editing = ref(null)
        const form = ref({ proto:'tcp', fromPort:'', toIp:'', toPort:'' })
        const conns = ref([]), est = ref([]), syn = ref([]), blocked = ref([]), white = ref([])
        const blkIp = ref(""), wIp = ref("")
        const cfg = ref({ ddosDefense:true, tcpSynPerIp:150, tcpSynBurst:300, tcpConnPerIp:250, udpPpsPerIp:8000, udpBurst:12000 })
        const fmt = t => t? new Date(t).toLocaleString('vi'):''
        const flash = (m,cls='alert-success') => { toast.value={msg:m,cls}; setTimeout(()=>toast.value=null,1600) }
        const go = t => { tab.value=t; if(t==='rules') fetchRules(); if(t==='lists') loadLists(); if(t==='blocked'){loadBlock()} if(t==='whitelist'){loadWhite()} if(t==='rate'){loadCfg()} }

        const fetchRules = async()=>{ rules.value = await (await fetch('/api/rules')).json() }
        const createRule = async()=>{
          const b=form.value; if(!b.fromPort||!b.toIp||!b.toPort){ flash("Điền đủ thông tin","alert-danger"); return }
          const body = { proto:b.proto, fromPort:String(b.fromPort), toIp:b.toIp, toPort:String(b.toPort) }
          const r = await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
          if(r.status===409){ flash("Port này đã được forward!","alert-danger"); return }
          if(!r.ok){ flash("Tạo rule thất bại","alert-danger"); return }
          form.value={ proto:'tcp', fromPort:'', toIp:'', toPort:'' }; flash("Đã tạo rule!"); fetchRules()
        }
        const toggleRule = async (r)=>{ const x=await fetch(`/api/rules/${r.id}/toggle`,{method:'POST'}); flash(x.ok?"Đã cập nhật":"Lỗi","alert-"+(x.ok?"success":"danger")); fetchRules() }
        const del = async (r)=>{ if(confirm("Xóa rule?")){ const x=await fetch(`/api/rules/${r.id}`,{method:'DELETE'}); flash(x.ok?"Đã xóa":"Lỗi","alert-"+(x.ok?"success":"danger")); fetchRules() } }
        const edit = (r)=>{ editing.value = {...r} }
        const saveEdit = async()=>{
          const b = editing.value, body={ proto:b.proto, fromPort:String(b.fromPort), toIp:b.toIp, toPort:String(b.toPort) }
          const x = await fetch(`/api/rules/${b.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
          if(x.status===409){ flash("Port này đã được forward!","alert-danger"); return }
          if(!x.ok){ flash("Không thể cập nhật","alert-danger"); return }
          editing.value=null; flash("Đã lưu!"); fetchRules()
        }

        const loadBlock = async()=>{ const d = await (await fetch('/api/blocked')).json(); blocked.value = d.ips||[] }
        const blockIP = async(ip)=>{ if(!ip) return; const r=await fetch('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); flash(r.ok?'Blocked':'Lỗi','alert-'+(r.ok?'success':'danger')); blkIp.value=""; loadBlock(); loadLists() }
        const unblockIP = async(ip)=>{ const r=await fetch('/api/unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); flash(r.ok?'Unblocked':'Lỗi','alert-'+(r.ok?'success':'danger')); loadBlock(); loadLists() }

        const loadWhite = async()=>{ const d = await (await fetch('/api/whitelisted')).json(); white.value = d.ips||[] }
        const whiteIP = async(ip)=>{ if(!ip) return; const r=await fetch('/api/whitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); flash(r.ok?'Whitelisted':'Lỗi','alert-'+(r.ok?'success':'danger')); wIp.value=""; loadWhite(); loadLists() }
        const unwhiteIP = async(ip)=>{ const r=await fetch('/api/unwhitelist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); flash(r.ok?'Removed':'Lỗi','alert-'+(r.ok?'success':'danger')); loadWhite(); loadLists() }

        const loadCfg = async()=>{ cfg.value = await (await fetch('/api/config')).json() }
        const saveCfg = async()=>{ const r = await fetch('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg.value)}); flash(r.ok?'Đã áp dụng':'Lưu lỗi','alert-'+(r.ok?'success':'danger')) }

        const loadConn = async()=>{
          const all = await (await fetch('/api/connections')).json()
          conns.value = all
          est.value = all.filter(x=>x.phase==='EST')
          syn.value = all.filter(x=>x.phase==='SYN')
        }
        const loadLists = async()=>{ await Promise.all([loadConn(), loadBlock(), loadWhite()]) }
        const blockAll = async()=>{ if(!confirm('Block toàn bộ IP hiện tại (trừ whitelist)?')) return; const r = await fetch('/api/blockall',{method:'POST'}); flash(r.ok?'Đã block all':'Lỗi','alert-'+(r.ok?'success':'danger')); loadLists() }

        onMounted(()=>{ fetchRules(); loadCfg(); loadLists(); setInterval(()=>{ if(tab.value==='lists'){ loadLists() } }, 1000) })
        return {tab,go,fmt,toast,form,rules,createRule,toggleRule,del,edit,editing,saveEdit,conns,est,syn,blocked,white,blkIp,wIp,blockIP,unblockIP,whiteIP,unwhiteIP,cfg,saveCfg,loadLists,blockAll}
      }
    }).mount('#app')
  </script>
</body>
</html>
HTML

echo "==> Build & service"
cd "$APP_DIR/backend"
[ -f rules.json ] || { echo "[]" > rules.json; chmod 666 rules.json; }
[ -f config.json ] || { cat > config.json <<JSON
{ "ddosDefense": true, "tcpSynPerIp": 150, "tcpSynBurst": 300, "tcpConnPerIp": 250, "udpPpsPerIp": 8000, "udpBurst": 12000 }
JSON
chmod 666 config.json; }

export PATH="/usr/local/go/bin:$PATH"
go mod tidy
go build -o portpanel main.go

cat > /etc/systemd/system/ifw.service <<EOF
[Unit]
Description=IFW DNAT Panel
After=network.target

[Service]
WorkingDirectory=$APP_DIR/backend
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
systemctl enable --now ifw.service >/dev/null
systemctl restart ifw.service

IP=$(curl -s4 https://api.ipify.org || hostname -I | awk '{print $1}')
echo
echo "==> HOÀN TẤT!"
echo "Panel:  http://$IP:$PANEL_PORT/adminsetupfw/"
echo "API:    /api/rules, /api/blocked, /api/whitelisted, /api/connections"
echo "Gợi ý:  tạo ít nhất 1 Rule rồi sang tab 'Danh sách IP' để theo dõi (auto 1s)."
