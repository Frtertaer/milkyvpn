// Command kal2-panel is a small web control panel for a kal2 (Pandora)
// server host: service/listener status, a share-link generator, a
// subscription endpoint clients can poll for fresh links, and a feature
// editor that rewrites the kal2 systemd unit via a drop-in and restarts it.
//
// Auth: a single admin token (-token / PANEL_TOKEN) exchanged for an
// HMAC-signed cookie. Serve over TLS (-tls autocert cache PEM) or keep the
// default localhost bind.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"

	"github.com/skip2/go-qrcode"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var indexHTML []byte

const (
	cookieName = "kal2p"
	cookieTTL  = 24 * time.Hour
)

// server flags the panel is allowed to touch on the kal2 unit; anything
// else in ExecStart is preserved verbatim.
var managedFlags = []string{
	"front-listen", "quic2-listen", "rtc-listen", "decoy", "steal",
	"echkeys", "egress-family", "upstream", "users-file", "stats-file",
}

const (
	usersFilePath = "/etc/kal2/users.json"
	statsFilePath = "/etc/kal2/stats.jsonl"
	// canaryPath is where the RU-side probe (deploy/canary-ru.sh, scp'd by
	// cron) drops its JSONL summary; panel reads it for the "входы из РФ" card.
	canaryPath = "/etc/kal2/canary-ru.jsonl"
	// canaryHistPath is the appended long-run log the same script maintains;
	// /api/canary/history renders latency/uptime trends from it.
	canaryHistPath = "/etc/kal2/canary-ru-history.jsonl"
	// histPoints caps samples per entry returned by the history API —
	// 144 × 10-min cron ≈ 24h of trend.
	histPoints = 144
	// auditPath is the admin action log; auditLimit bounds /api/audit output.
	auditPath  = "/etc/kal2/audit.jsonl"
	auditLimit = 200
)

// panelUser is a provisioned client: the panel owns id/psk/subscription and
// mirrors enabled users into the server's -users-file.
type panelUser struct {
	ID        string `json:"id"`
	PSK       string `json:"psk"` // hex
	Created   int64  `json:"created"`
	Disabled  bool   `json:"disabled"`
	SubToken  string `json:"sub_token"`
	QuotaMB   int64  `json:"quota_mb,omitempty"`   // total traffic allowed per calendar month; 0 = unlimited
	ExpiresAt int64  `json:"expires_at,omitempty"` // unix; 0 = never
}

type panelStore struct {
	SubToken string      `json:"sub_token"`
	Pub      string      `json:"pub"`     // server ed25519 public key (hex)
	ECH      string      `json:"ech"`     // optional ech= link param
	Entries  []entry     `json:"entries"` // dialable endpoints for the link generator
	Fronts   []entry     `json:"fronts"`  // deployed front relays
	Links    []string    `json:"links"`   // subscription payload served at /sub/<token>
	Users    []panelUser `json:"users"`   // provisioned clients; enabled ones land in users.json
	// SubDisabled switches the /sub/<token> endpoint off centrally: clients
	// keep their last fetched links and the refresh silently no-ops (the app
	// treats 404 as subscription_not_found and retains the snapshot).
	SubDisabled bool `json:"sub_disabled"`
	// TOTPSecret (hex) enables 2FA on panel login: the admin token AND a
	// current authenticator code are both required. Empty = disabled.
	TOTPSecret string `json:"totp_secret,omitempty"`
}

type entry struct {
	Label string `json:"label"`
	Addr  string `json:"addr"` // entries: host:port · fronts: https URL
	URL   string `json:"url,omitempty"`
}

type panel struct {
	mu         sync.Mutex
	store      panelStore
	path       string
	token      []byte
	unit       string
	quasar     string
	pubOrigin  string
	totpPending []byte // secret awaiting confirmation via /api/totp/enable
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9443", "panel listen addr")
	tlsFile := flag.String("tls", "", "PEM file containing both the cert chain and key (e.g. an autocert cache file); empty = plain HTTP")
	token := flag.String("token", os.Getenv("PANEL_TOKEN"), "admin token (or PANEL_TOKEN env)")
	data := flag.String("data", "/etc/kal2/panel.json", "panel state file")
	unit := flag.String("unit", "kal2.service", "managed systemd unit")
	quasar := flag.String("unit-quasar", "kal2-quasar.service", "quasar UDP unit (toggled by the udp-listen switch)")
	pubOrigin := flag.String("pub-origin", "", "public base URL for the subscription link, e.g. https://kal.example:9443 (empty = request Host)")
	ops := flag.String("ops-listen", "", "loopback-only ops API addr, e.g. 127.0.0.1:9449 — no auth, never expose externally (used by the tg-bot helper)")
	flag.Parse()

	if *token == "" {
		log.Fatal("need -token or PANEL_TOKEN")
	}
	p := &panel{
		path:      *data,
		token:     []byte(*token),
		unit:      *unit,
		quasar:    *quasar,
		pubOrigin: strings.TrimRight(*pubOrigin, "/"),
	}
	p.load()

	if *ops != "" {
		om := http.NewServeMux()
		om.HandleFunc("/ops/status", p.opsStatus)
		om.HandleFunc("/ops/users", p.opsUsers)
		om.HandleFunc("/ops/rotate-all", p.rotateAll)
		go func() {
			log.Printf("kal2-panel: ops api on http://%s (loopback only)", *ops)
			if err := http.ListenAndServe(*ops, om); err != nil {
				log.Printf("ops listener: %v", err)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.ui)
	mux.HandleFunc("/api/login", p.login)
	mux.HandleFunc("/api/logout", p.logout)
	mux.HandleFunc("/api/status", p.auth(p.status))
	mux.HandleFunc("/api/config", p.auth(p.config))
	mux.HandleFunc("/api/links", p.auth(p.links))
	mux.HandleFunc("/api/genlink", p.auth(p.genlink))
	mux.HandleFunc("/api/users", p.auth(p.users))
	mux.HandleFunc("/api/stats", p.auth(p.stats))
	mux.HandleFunc("/api/qr", p.auth(p.qr))
	mux.HandleFunc("/api/password", p.auth(p.password))
	mux.HandleFunc("/api/backup", p.auth(p.backup))
	mux.HandleFunc("/api/canary/history", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"series": canaryHistory(canaryHistPath)})
	}))
	mux.HandleFunc("/api/traffic", p.auth(func(w http.ResponseWriter, r *http.Request) {
		h, d := trafficSeries(p.statsPath())
		writeJSON(w, map[string]any{"hourly": h, "daily": d})
	}))
	mux.HandleFunc("/api/audit", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"events": auditTail(auditPath, auditLimit)})
	}))
	mux.HandleFunc("/api/totp/status", p.auth(p.totpStatus))
	mux.HandleFunc("/api/totp/begin", p.auth(p.totpBegin))
	mux.HandleFunc("/api/totp/enable", p.auth(p.totpEnable))
	mux.HandleFunc("/api/totp/disable", p.auth(p.totpDisable))
	mux.HandleFunc("/sub/", p.sub)

	go p.enforceWatch()

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if *tlsFile != "" {
		log.Printf("kal2-panel: https://%s", *listen)
		log.Fatal(srv.ListenAndServeTLS(*tlsFile, *tlsFile))
	}
	log.Printf("kal2-panel: http://%s (plain HTTP — pass -tls for HTTPS)", *listen)
	log.Fatal(srv.ListenAndServe())
}

// ------------------------------------------------------------------ store

func (p *panel) load() {
	b, err := os.ReadFile(p.path)
	if err == nil {
		_ = json.Unmarshal(b, &p.store)
	}
	if p.store.SubToken == "" {
		p.store.SubToken = randHex(16)
	}
	if p.store.Pub == "" {
		p.store.Pub = derivePubFromUnit(p.unit)
	}
	// Import -user flags once: existing deployments provisioned clients on
	// the unit command line; the panel adopts them into its own user store.
	if len(p.store.Users) == 0 {
		args := unitArgs(p.unit)
		for i, a := range args {
			if a == "-user" && i+1 < len(args) {
				id, psk, ok := strings.Cut(args[i+1], "=")
				if ok && id != "" && psk != "" {
					p.store.Users = append(p.store.Users, panelUser{
						ID: id, PSK: psk, Created: time.Now().Unix(), SubToken: randHex(16),
					})
				}
			}
		}
	}
	for i := range p.store.Users {
		if p.store.Users[i].SubToken == "" {
			p.store.Users[i].SubToken = randHex(16)
		}
	}
	p.save()
}

func (p *panel) save() {
	b, _ := json.MarshalIndent(&p.store, "", "  ")
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err == nil {
		_ = os.Rename(tmp, p.path)
	}
}

// pub = last 64 hex chars of the -identity ed25519 key (seed+pub layout).
func derivePubFromUnit(unit string) string {
	args := unitArgs(unit)
	for i, a := range args {
		if a == "-identity" && i+1 < len(args) && len(args[i+1]) >= 64 {
			return args[i+1][len(args[i+1])-64:]
		}
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ------------------------------------------------------------------ auth

func (p *panel) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
		Code  string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if subtle.ConstantTimeCompare([]byte(in.Token), p.token) != 1 {
		p.audit(r, "login_fail", "")
		http.Error(w, "bad token", 401)
		return
	}
	p.mu.Lock()
	totpHex := p.store.TOTPSecret
	p.mu.Unlock()
	if totpHex != "" {
		secret, err := hex.DecodeString(totpHex)
		if err != nil || !totpVerify(secret, in.Code) {
			p.audit(r, "login_fail", "totp")
			http.Error(w, "bad totp code", 401)
		return
		}
	}
	p.audit(r, "login", "")
	exp := time.Now().Add(cookieTTL).Unix()
	mac := hmac.New(sha256.New, p.token)
	fmt.Fprintf(mac, "%d", exp)
	v := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d.%x", exp, mac.Sum(nil))))
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: v, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	w.Write([]byte("{}"))
}

func (p *panel) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	w.Write([]byte("{}"))
}

func (p *panel) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		ok := false
		if err == nil {
			if raw, derr := base64.RawURLEncoding.DecodeString(c.Value); derr == nil {
				parts := strings.SplitN(string(raw), ".", 2)
				if len(parts) == 2 {
					if exp, cerr := strconv.ParseInt(parts[0], 10, 64); cerr == nil && exp > time.Now().Unix() {
						mac := hmac.New(sha256.New, p.token)
						fmt.Fprintf(mac, "%d", exp)
						want := fmt.Sprintf("%x", mac.Sum(nil))
						ok = subtle.ConstantTimeCompare([]byte(parts[1]), []byte(want)) == 1
					}
				}
			}
		}
		if !ok {
			http.Error(w, "auth", 401)
			return
		}
		next(w, r)
	}
}

func (p *panel) ui(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// ------------------------------------------------------------------ status

type statusReply struct {
	Unit       string   `json:"unit"`
	UnitActive bool     `json:"unit_active"`
	Uptime     string   `json:"uptime"`
	Quic2      bool     `json:"quic2"`
	Listeners  []lnr    `json:"listeners"`
	Journal    string   `json:"journal"`
	Canary     []canRec `json:"canary"` // latest RU-side probe per entry; empty until deployed
}

// canRec is one liveness probe pushed by the RU canary host
// (deploy/canary-ru.sh → scp'd to canaryPath).
type canRec struct {
	TS      string `json:"ts"`
	Entry   string `json:"entry"`
	Carrier string `json:"carrier"`
	OK      bool   `json:"ok"`
	Ms      int64  `json:"ms"`
}

// canSeries is the per-entry trend the history card renders: ordered
// samples plus pre-computed uptime/avg so the UI stays dumb.
type canSeries struct {
	Entry   string    `json:"entry"`
	Carrier string    `json:"carrier"`
	Uptime  float64   `json:"uptime"` // % of ok samples in the window
	AvgMs   int64     `json:"avg_ms"`
	Pts     []canPoint `json:"pts"`
}

type canPoint struct {
	TS string `json:"ts"`
	OK bool   `json:"ok"`
	Ms int64  `json:"ms"`
}

// canaryHistory reads the appended long-run JSONL and returns each
// entry+carrier's newest histPoints samples in time order.
func canaryHistory(path string) []canSeries {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	byKey := map[string]*canSeries{}
	var order []string
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r canRec
		if json.Unmarshal([]byte(ln), &r) != nil {
			continue
		}
		k := r.Entry + "|" + r.Carrier
		s := byKey[k]
		if s == nil {
			s = &canSeries{Entry: r.Entry, Carrier: r.Carrier}
			byKey[k] = s
			order = append(order, k)
		}
		s.Pts = append(s.Pts, canPoint{TS: r.TS, OK: r.OK, Ms: r.Ms})
		if len(s.Pts) > histPoints {
			s.Pts = s.Pts[len(s.Pts)-histPoints:]
		}
	}
	var out []canSeries
	for _, k := range order {
		s := byKey[k]
		var ok, msSum, msN int64
		for _, p := range s.Pts {
			if p.OK {
				ok++
				msSum += p.Ms
				msN++
			}
		}
		if len(s.Pts) > 0 {
			s.Uptime = float64(ok) * 100 / float64(len(s.Pts))
		}
		if msN > 0 {
			s.AvgMs = msSum / msN
		}
		out = append(out, *s)
	}
	return out
}

// canaryLatest reads the JSONL the RU probe writes and keeps the newest
// record per entry+carrier, newest first.
func canaryLatest(path string) []canRec {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []canRec
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var r canRec
		if json.Unmarshal([]byte(lines[i]), &r) != nil {
			continue
		}
		k := r.Entry + "|" + r.Carrier
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

type lnr struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Up    bool   `json:"up"`
}

func (p *panel) status(w http.ResponseWriter, r *http.Request) {
	active := strings.TrimSpace(sh("systemctl", "is-active", p.unit)) == "active"
	st := statusReply{Unit: p.unit, UnitActive: active}

	ts := sh("systemctl", "show", p.unit, "-p", "ActiveEnterTimestamp", "--value")
	if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(ts)); err == nil && active {
		st.Uptime = time.Since(t).Round(time.Second).String()
	}
	args := unitArgs(p.unit)
	flagMap := map[string][]string{}
	for i, a := range args {
		if strings.HasPrefix(a, "-") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flagMap[a[1:]] = append(flagMap[a[1:]], args[i+1])
		}
	}
	add := func(proto string, csv string) {
		for _, addr := range strings.Split(csv, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" || addr == "off" {
				continue
			}
			st.Listeners = append(st.Listeners, lnr{proto, addr, listenerUp(proto, addr)})
		}
	}
	for _, f := range []string{"quic2-listen", "front-listen"} {
		proto := "udp"
		if f == "front-listen" {
			proto = "tcp"
		}
		for _, v := range flagMap[f] {
			add(proto, v)
		}
	}
	if v := flagMap["listen"]; len(v) > 0 {
		add("tcp", v[0]) // veil/decoy TLS
	}
	if q := unitArgs(p.quasar); len(q) > 0 && strings.TrimSpace(sh("systemctl", "is-active", p.quasar)) == "active" {
		for i, a := range q {
			if a == "-udp-listen" && i+1 < len(q) {
				st.Listeners = append(st.Listeners, lnr{"udp", q[i+1], listenerUp("udp", q[i+1])})
			}
		}
	}
	st.Quic2 = len(flagMap["quic2-listen"]) > 0
	st.Journal = sh("journalctl", "-u", p.unit, "-u", p.quasar, "-n", "30", "--no-pager", "-o", "short-iso")
	st.Canary = canaryLatest(canaryPath)
	writeJSON(w, st)
}

func listenerUp(proto, addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	out := sh("ss", map[bool]string{true: "-tlnH", false: "-ulnH"}[proto == "tcp"], "sport", "=", ":"+port)
	return strings.Contains(out, ":"+port)
}

// ------------------------------------------------------------------ config

var execStartRe = regexp.MustCompile(`(?m)^ExecStart=(.*)$`)

// parseExecStart returns the argv of the effective ExecStart inside a
// `systemctl cat` dump: systemd merges main file + drop-ins and the LAST
// non-empty ExecStart= line wins.
func parseExecStart(cat string) []string {
	var argv []string
	for _, m := range execStartRe.FindAllStringSubmatch(cat, -1) {
		// Empty ExecStart= clears the accumulated list (that's how drop-ins
		// override); a later non-empty line then wins.
		if f := strings.Fields(m[1]); len(f) > 0 {
			argv = f
		} else {
			argv = nil
		}
	}
	return argv
}

func unitArgs(unit string) []string {
	return parseExecStart(sh("systemctl", "cat", unit))
}

func (p *panel) config(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		args := unitArgs(p.unit)
		flags := map[string]string{}
		for i, a := range args {
			if strings.HasPrefix(a, "-") {
				name := a[1:]
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					for _, mf := range managedFlags {
						if name == mf {
							flags[name] = args[i+1]
						}
					}
				}
			}
		}
		// quasar toggle surfaces as udp-listen
		if strings.TrimSpace(sh("systemctl", "is-enabled", p.quasar)) == "enabled" {
			flags["udp-listen"] = "on"
		}
		writeJSON(w, map[string]any{"flags": flags})
		return
	}

	var in struct {
		Flags map[string]string `json:"flags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	args := unitArgs(p.unit)
	if len(args) == 0 {
		http.Error(w, "unit has no ExecStart", 500)
		return
	}
	bin := args[0]
	// rebuild: keep unmanaged flags verbatim, apply managed ones
	var kept []string
	for i := 1; i < len(args); {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			kept = append(kept, a)
			i++
			continue
		}
		name := a[1:]
		hasVal := i+1 < len(args) && !strings.HasPrefix(args[i+1], "-")
		managed := false
		for _, mf := range managedFlags {
			if name == mf || name == "udp-listen" {
				managed = true
			}
		}
		if managed {
			i++
			if hasVal {
				i++ // drop managed flag + old value
			}
			continue
		}
		kept = append(kept, a)
		if hasVal {
			kept = append(kept, args[i+1])
			i += 2
		} else {
			i++
		}
	}
	for _, f := range managedFlags {
		if v := strings.TrimSpace(in.Flags[f]); v != "" && f != "udp-listen" {
			kept = append(kept, "-"+f, v)
		}
	}
	newExec := bin + " " + strings.Join(kept, " ")

	dir := "/etc/systemd/system/" + p.unit + ".d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	drop := filepath.Join(dir, "zz-panel.conf")
	prev, _ := os.ReadFile(drop)
	_ = os.WriteFile(drop+".bak", prev, 0600)
	conf := fmt.Sprintf("[Service]\nExecStart=\nExecStart=%s\n", newExec)
	if err := os.WriteFile(drop, []byte(conf), 0644); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		http.Error(w, "daemon-reload: "+string(out), 500)
		return
	}
	if out, err := exec.Command("systemctl", "restart", p.unit).CombinedOutput(); err != nil {
		http.Error(w, "restart: "+string(out), 500)
		return
	}
	// quasar toggle
	if _, on := in.Flags["udp-listen"]; on {
		exec.Command("systemctl", "enable", "--now", p.quasar).Run()
	} else {
		exec.Command("systemctl", "disable", "--now", p.quasar).Run()
	}
	p.audit(r, "apply", fmt.Sprintf("flags=%v", in.Flags))
	writeJSON(w, map[string]bool{"ok": true})
}

// ------------------------------------------------------------------ links

func (p *panel) links(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method == http.MethodPost {
		var in struct {
			Add         string `json:"add"`
			SubDisabled *bool  `json:"sub_disabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if in.SubDisabled != nil {
			p.store.SubDisabled = *in.SubDisabled
			p.audit(r, "sub_toggle", fmt.Sprintf("disabled=%v", *in.SubDisabled))
		}
		if in.Add != "" && strings.HasPrefix(in.Add, "kal2://") {
			dup := false
			for _, l := range p.store.Links {
				if l == in.Add {
					dup = true
				}
			}
			if !dup {
				p.store.Links = append(p.store.Links, in.Add)
				p.audit(r, "link_add", in.Add)
			}
			p.save()
		}
	}
	writeJSON(w, map[string]any{
		"entries":     p.store.Entries,
		"fronts":      p.store.Fronts,
		"links":       p.store.Links,
		"sub_url":     p.subURL(r),
		"auto_update": !p.store.SubDisabled,
	})
}

func (p *panel) subURL(r *http.Request) string {
	base := p.pubOrigin
	if base == "" {
		base = "https://" + r.Host
	}
	return base + "/sub/" + p.store.SubToken
}

// GET /sub/<token> — the auto-update endpoint a client polls. The global
// token serves the saved link list as-is; a per-user token serves the same
// links with that user's PSK stamped in (kal2://<psk>@ — credentials are
// always the first authority field).
func (p *panel) sub(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.URL.Path, "/sub/")
	p.mu.Lock()
	disabled := p.store.SubDisabled
	var links []string
	ok := subtle.ConstantTimeCompare([]byte(tok), []byte(p.store.SubToken)) == 1
	if ok {
		links = append(links, p.store.Links...)
	} else {
		for _, u := range p.store.Users {
			if u.Disabled || subtle.ConstantTimeCompare([]byte(tok), []byte(u.SubToken)) != 1 {
				continue
			}
			for _, l := range p.store.Links {
				links = append(links, rekeyLink(l, u.PSK))
			}
			ok = true
			break
		}
	}
	p.mu.Unlock()
	if !ok || disabled {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(strings.Join(links, "\n")))
}

var linkCredsRe = regexp.MustCompile(`^(kal2://)[^@/?]*@`)

// rekeyLink replaces the credentials segment of a kal2:// link.
func rekeyLink(link, psk string) string {
	if !linkCredsRe.MatchString(link) {
		return link
	}
	return linkCredsRe.ReplaceAllString(link, "${1}"+psk+"@")
}

func (p *panel) genlink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Addrs   []string `json:"addrs"`
		Fronts  []string `json:"fronts"`
		Carrier string   `json:"carrier"`
		SNI     string   `json:"sni"`
		User    string   `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	p.mu.Lock()
	st := p.store
	p.mu.Unlock()
	if len(in.Addrs) == 0 {
		http.Error(w, "pick at least one entry", 400)
		return
	}
	psk := ""
	if in.User != "" {
		for _, u := range st.Users {
			if u.ID == in.User {
				psk = u.PSK
				break
			}
		}
		if psk == "" {
			http.Error(w, "unknown user", 400)
			return
		}
	} else {
		psk = unitUserPSK(p.unit)
		if psk == "" && len(st.Users) > 0 {
			psk = st.Users[0].PSK
		}
	}
	if psk == "" || st.Pub == "" {
		http.Error(w, "server credentials unknown — check the unit", 500)
		return
	}
	primary := in.Addrs[0]
	q := []string{
		"sni=" + or(in.SNI, "kal.mergescribe.dev"),
		"pub=" + st.Pub,
		"carrier=" + or(in.Carrier, "auto"),
	}
	if st.ECH != "" {
		q = append(q, "ech="+st.ECH)
	}
	if len(in.Addrs) > 1 {
		q = append(q, "alt="+strings.Join(in.Addrs[1:], ","))
	}
	for _, f := range in.Fronts {
		q = append(q, "front="+url.QueryEscape(f))
	}
	link := "kal2://" + psk + "@" + primary + "?" + strings.Join(q, "&")
	writeJSON(w, map[string]string{"link": link})
}

// unitUserPSK pulls the first `-user id=psk` value from the unit's
// ExecStart and returns its psk part.
func unitUserPSK(unit string) string {
	args := unitArgs(unit)
	for i, a := range args {
		if a == "-user" && i+1 < len(args) {
			if _, psk, ok := strings.Cut(args[i+1], "="); ok {
				return psk
			}
		}
	}
	return ""
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// ------------------------------------------------------------------ users

var userIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

// writeUsersFile mirrors enabled panel users into the server's users-file;
// the listener re-reads it on mtime change — no restart needed. Enabled means
// not admin-disabled, not expired, and under quota for the current month.
// Identical content is left in place (avoids pointless mtime-triggered reloads).
func (p *panel) writeUsersFile() error {
	now := time.Now().Unix()
	month := p.monthUsage()
	type fu struct {
		ID  string `json:"id"`
		PSK string `json:"psk"`
	}
	var out []fu
	for _, u := range p.store.Users {
		if !u.active(month[u.ID], now) {
			continue
		}
		out = append(out, fu{ID: u.ID, PSK: u.PSK})
	}
	b, _ := json.Marshal(out)
	if old, err := os.ReadFile(usersFilePath); err == nil && string(old) == string(b) {
		return nil
	}
	tmp := usersFilePath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(usersFilePath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, usersFilePath)
}

// active reports whether the user should appear in the server's users-file:
// not admin-disabled, not expired, under monthly quota.
func (u panelUser) active(monthBytes uint64, now int64) bool {
	if u.Disabled {
		return false
	}
	if u.ExpiresAt > 0 && now > u.ExpiresAt {
		return false
	}
	if u.QuotaMB > 0 && monthBytes >= uint64(u.QuotaMB)<<20 {
		return false
	}
	return true
}

// enforceWatch expires quota/time-limited users on a 60s cadence: a user who
// crosses their quota mid-month stops authenticating within a minute — no
// admin action, no restart (the listener just sees a shorter users file).
func (p *panel) enforceWatch() {
	for {
		time.Sleep(60 * time.Second)
		p.mu.Lock()
		err := p.writeUsersFile()
		p.mu.Unlock()
		if err != nil {
			log.Printf("users-file enforce: %v", err)
		}
	}
}

// fileMode reports whether the unit already consumes the users-file.
func (p *panel) fileMode() bool {
	args := unitArgs(p.unit)
	for i, a := range args {
		if a == "-users-file" && i+1 < len(args) {
			return true
		}
	}
	return false
}

// ensureUserMode migrates the unit to -users-file/-stats-file once: strips
// -user flags and rewrites ExecStart via the panel drop-in, then restarts.
// Runs only on the first user mutation; no-op when already migrated.
func (p *panel) ensureUserMode() error {
	if err := p.writeUsersFile(); err != nil {
		return err
	}
	args := unitArgs(p.unit)
	hasUserFlag, hasUsersFile := false, false
	for _, a := range args {
		if a == "-user" {
			hasUserFlag = true
		}
		if a == "-users-file" {
			hasUsersFile = true
		}
	}
	if !hasUserFlag && hasUsersFile {
		return nil
	}
	bin := args[0]
	var kept []string
	for i := 1; i < len(args); {
		a := args[i]
		if a == "-user" {
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "-") {
				i++ // drop -user + value
			}
			continue
		}
		kept = append(kept, a)
		i++
	}
	if !hasUsersFile {
		kept = append(kept, "-users-file", usersFilePath)
	}
	if !strings.Contains(strings.Join(kept, " "), "-stats-file") {
		kept = append(kept, "-stats-file", statsFilePath)
	}
	dir := "/etc/systemd/system/" + p.unit + ".d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	drop := filepath.Join(dir, "zz-panel.conf")
	prev, _ := os.ReadFile(drop)
	_ = os.WriteFile(drop+".bak", prev, 0600)
	conf := fmt.Sprintf("[Service]\nExecStart=\nExecStart=%s %s\n", bin, strings.Join(kept, " "))
	if err := os.WriteFile(drop, []byte(conf), 0644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %s", out)
	}
	if out, err := exec.Command("systemctl", "restart", p.unit).CombinedOutput(); err != nil {
		return fmt.Errorf("restart: %s", out)
	}
	return nil
}

func (p *panel) users(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method == http.MethodPost {
		var in struct {
			Add       string `json:"add"`
			Del       string `json:"del"`
			Disable   string `json:"disable"`
			Disabled  bool   `json:"disabled"`
			Rekey     string `json:"rekey"`
			Set       string `json:"set"`
			QuotaMB   int64  `json:"quota_mb"`
			ExpiresAt int64  `json:"expires_at"`
			RotateAll bool   `json:"rotate_all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		switch {
		case in.RotateAll:
			n := p.rotateAllLocked()
			p.audit(r, "user_rotate_all", fmt.Sprintf("%d users", n))
		case in.Add != "":
			id := strings.TrimSpace(in.Add)
			if !userIDRe.MatchString(id) {
				http.Error(w, "id: 1-32 [a-z0-9_-]", 400)
				return
			}
			for _, u := range p.store.Users {
				if u.ID == id {
					http.Error(w, "user exists", 409)
					return
				}
			}
			p.store.Users = append(p.store.Users, panelUser{
				ID: id, PSK: randHex(32), Created: time.Now().Unix(), SubToken: randHex(16),
			})
			p.audit(r, "user_add", id)
		case in.Del != "":
			n := len(p.store.Users)
			out := p.store.Users[:0]
			for _, u := range p.store.Users {
				if u.ID != in.Del {
					out = append(out, u)
				}
			}
			p.store.Users = out
			if len(out) == n {
				http.Error(w, "no such user", 404)
				return
			}
			p.audit(r, "user_del", in.Del)
		case in.Disable != "":
			found := false
			for i := range p.store.Users {
				if p.store.Users[i].ID == in.Disable {
					p.store.Users[i].Disabled = in.Disabled
					found = true
				}
			}
			if !found {
				http.Error(w, "no such user", 404)
				return
			}
			p.audit(r, "user_disable", fmt.Sprintf("%s=%v", in.Disable, in.Disabled))
		case in.Rekey != "":
			found := false
			for i := range p.store.Users {
				if p.store.Users[i].ID == in.Rekey {
					p.store.Users[i].PSK = randHex(32)
					p.store.Users[i].SubToken = randHex(16)
					found = true
				}
			}
			if !found {
				http.Error(w, "no such user", 404)
				return
			}
			p.audit(r, "user_rekey", in.Rekey)
		case in.Set != "":
			if in.QuotaMB < 0 || in.ExpiresAt < 0 {
				http.Error(w, "quota/expiry must be >= 0", 400)
				return
			}
			found := false
			for i := range p.store.Users {
				if p.store.Users[i].ID == in.Set {
					p.store.Users[i].QuotaMB = in.QuotaMB
					p.store.Users[i].ExpiresAt = in.ExpiresAt
					found = true
				}
			}
			if !found {
				http.Error(w, "no such user", 404)
				return
			}
			p.audit(r, "user_set", fmt.Sprintf("%s quota=%dMB exp=%d", in.Set, in.QuotaMB, in.ExpiresAt))
		default:
			http.Error(w, "empty op", 400)
			return
		}
		p.save()
		if err := p.ensureUserMode(); err != nil {
			http.Error(w, "applied but unit update failed: "+err.Error(), 500)
			return
		}
		// Mutations migrate the unit to users-file mode once — a one-time
		// restart; later add/remove/rekey are picked up via file mtime.
	}
	type uout struct {
		ID        string `json:"id"`
		Created   int64  `json:"created"`
		Disabled  bool   `json:"disabled"`
		SubURL    string `json:"sub_url"`
		QuotaMB   int64  `json:"quota_mb"`
		ExpiresAt int64  `json:"expires_at"`
	}
	users := make([]uout, 0, len(p.store.Users))
	for _, u := range p.store.Users {
		base := p.pubOrigin
		if base == "" {
			base = "https://" + r.Host
		}
		users = append(users, uout{u.ID, u.Created, u.Disabled, base + "/sub/" + u.SubToken, u.QuotaMB, u.ExpiresAt})
	}
	writeJSON(w, map[string]any{"users": users, "file_mode": p.fileMode()})
}

// ------------------------------------------------------------------ stats

type statAgg struct {
	Up       uint64 `json:"up"`
	Down     uint64 `json:"down"`
	Month    uint64 `json:"month"` // up+down bytes in the current calendar month — quota accounting
	Sessions int    `json:"sessions"`
	LastSeen int64  `json:"last_seen"`
	Online   int    `json:"online"`
}

// ------------------------------------------------------------------ ops API

// rotateAllLocked assigns fresh PSKs to every ENABLED user, keeping sub
// tokens (and therefore subscription URLs) stable — rotated links rekey
// automatically on the client's next subscription fetch. Caller holds p.mu
// or runs before serving; returns the count rotated.
func (p *panel) rotateAllLocked() int {
	n := 0
	for i := range p.store.Users {
		if p.store.Users[i].Disabled {
			continue
		}
		p.store.Users[i].PSK = randHex(32)
		n++
	}
	return n
}

// rotateAll exposes rotate-all on both the authed /api/users op and the
// loopback ops mux. POST only.
func (p *panel) rotateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	p.mu.Lock()
	n := p.rotateAllLocked()
	p.audit(r, "user_rotate_all", fmt.Sprintf("%d users (ops)", n))
	p.save()
	p.mu.Unlock()
	if err := p.ensureUserMode(); err != nil {
		http.Error(w, "rotated but unit update failed: "+err.Error(), 500)
		return
	}
	writeJSON(w, map[string]any{"rotated": n})
}

// opsStatus is the tg-bot's health probe: panel side state only.
func (p *panel) opsStatus(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	enabled := 0
	for _, u := range p.store.Users {
		if !u.Disabled {
			enabled++
		}
	}
	writeJSON(w, map[string]any{
		"users":         len(p.store.Users),
		"users_enabled": enabled,
		"file_mode":     p.fileMode(),
	})
}

// opsUsers: GET lists users for the tg-bot; POST {"id","disabled"} toggles
// one user — same mutation path the UI uses (save + ensureUserMode).
func (p *panel) opsUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.mu.Lock()
		users := append([]panelUser(nil), p.store.Users...)
		p.mu.Unlock()
		writeJSON(w, map[string]any{"users": users})
	case http.MethodPost:
		var in struct {
			ID       string `json:"id"`
			Disabled bool   `json:"disabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.ID == "" {
			http.Error(w, "need {id,disabled}", 400)
			return
		}
		p.mu.Lock()
		found := false
		for i := range p.store.Users {
			if p.store.Users[i].ID == in.ID {
				p.store.Users[i].Disabled = in.Disabled
				found = true
			}
		}
		if !found {
			p.mu.Unlock()
			http.Error(w, "no such user", 404)
			return
		}
		p.audit(r, "user_disable", fmt.Sprintf("%s=%v (ops)", in.ID, in.Disabled))
		p.save()
		p.mu.Unlock()
		if err := p.ensureUserMode(); err != nil {
			http.Error(w, "applied but unit update failed: "+err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "id": in.ID, "disabled": in.Disabled})
	default:
		http.Error(w, "GET/POST", 405)
	}
}

// ------------------------------------------------------------------ QR

// qr serves a PNG of the user's subscription URL for phone import.
func (p *panel) qr(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("t")
	if tok == "" {
		http.Error(w, "need ?t=", 400)
		return
	}
	base := p.pubOrigin
	if base == "" {
		base = "https://" + r.Host
	}
	png, err := qrcode.Encode(base+"/sub/"+tok, qrcode.Medium, 280)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// ------------------------------------------------------------------ password

// password changes the admin token: writes a systemd drop-in so the new
// token survives restarts, then swaps it in-memory — no restart, current
// cookies just expire (HMAC keys off the token).
func (p *panel) password(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cur string `json:"cur"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.New) < 16 {
		http.Error(w, "need cur + new (>=16 chars)", 400)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if in.Cur != string(p.token) {
		http.Error(w, "wrong current token", 403)
		return
	}
	dir := "/etc/systemd/system/kal2-panel.service.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	drop := filepath.Join(dir, "zz-token.conf")
	conf := fmt.Sprintf("[Service]\nEnvironment=PANEL_TOKEN=%s\n", in.New)
	if err := os.WriteFile(drop, []byte(conf), 0600); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		http.Error(w, fmt.Sprintf("token saved but daemon-reload failed: %s", out), 500)
		return
	}
	p.token = []byte(in.New)
	p.audit(r, "password_change", "")
	writeJSON(w, map[string]any{"ok": true})
}

// ------------------------------------------------------------------ 2FA (TOTP)

func (p *panel) totpStatus(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	writeJSON(w, map[string]any{"enabled": p.store.TOTPSecret != ""})
}

// totpBegin generates a pending secret and returns its otpauth URI — the
// caller renders it as a QR via /api/qr?text=. Nothing is persisted until
// enable confirms a valid code, so an interrupted setup can't lock the
// admin out.
func (p *panel) totpBegin(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.store.TOTPSecret != "" {
		http.Error(w, "totp already enabled", 400)
		return
	}
	secret, b32 := totpNewSecret()
	p.totpPending = secret
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	writeJSON(w, map[string]any{"secret": b32, "uri": totpURI(b32, "MilkyVPN", host)})
}

func (p *panel) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.totpPending == nil {
		http.Error(w, "call /api/totp/begin first", 400)
		return
	}
	if !totpVerify(p.totpPending, in.Code) {
		http.Error(w, "bad code", 403)
		return
	}
	p.store.TOTPSecret = hex.EncodeToString(p.totpPending)
	p.totpPending = nil
	p.save()
	p.audit(r, "totp_enable", "")
	writeJSON(w, map[string]any{"ok": true})
}

func (p *panel) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.store.TOTPSecret == "" {
		http.Error(w, "totp not enabled", 400)
		return
	}
	secret, err := hex.DecodeString(p.store.TOTPSecret)
	if err != nil || !totpVerify(secret, in.Code) {
		http.Error(w, "bad code", 403)
		return
	}
	p.store.TOTPSecret = ""
	p.save()
	p.audit(r, "totp_disable", "")
	writeJSON(w, map[string]any{"ok": true})
}

// ------------------------------------------------------------------ backup

// backup returns panel.json + users.json as one downloadable JSON.
func (p *panel) backup(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	panelB, _ := os.ReadFile(p.path)
	p.mu.Unlock()
	usersB, _ := os.ReadFile(usersFilePath)
	out, _ := json.Marshal(map[string]json.RawMessage{
		"panel": json.RawMessage(panelB),
		"users": json.RawMessage(usersB),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="kal2-backup.json"`)
	w.Write(out)
	p.audit(r, "backup", "")
}

func (p *panel) statsPath() string {
	path := statsFilePath
	args := unitArgs(p.unit)
	for i, a := range args {
		if a == "-stats-file" && i+1 < len(args) {
			path = args[i+1]
		}
	}
	return path
}

// parseStats folds the JSONL accounting log: per-uid totals, sessions, online
// (reset at the last boot marker), and this-month bytes for quota checks.
func parseStats(path string) (map[string]*statAgg, int64) {
	per := map[string]*statAgg{}
	online := map[string]int{}
	boot := int64(0)
	monthStart := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.Local).Unix()
	f, err := os.Open(path)
	if err != nil {
		return per, boot
	}
	defer f.Close()
	var rec struct {
		T    int64  `json:"t"`
		Ev   string `json:"ev"`
		UID  string `json:"uid"`
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	}
	dec := json.NewDecoder(f)
	for {
		if err := dec.Decode(&rec); err != nil {
			break // EOF or a torn tail line — stop at it
		}
		if rec.Ev == "boot" {
			boot = rec.T
			online = map[string]int{} // earlier opens died with the process
			continue
		}
		a := per[rec.UID]
		if a == nil {
			a = &statAgg{}
			per[rec.UID] = a
		}
		if rec.T > a.LastSeen {
			a.LastSeen = rec.T
		}
		switch rec.Ev {
		case "open":
			a.Sessions++
			online[rec.UID]++
		case "close":
			a.Up += rec.Up
			a.Down += rec.Down
			if rec.T >= monthStart {
				a.Month += rec.Up + rec.Down
			}
			if online[rec.UID] > 0 {
				online[rec.UID]--
			}
		}
	}
	for uid, n := range online {
		if n > 0 {
			per[uid].Online = n
		}
	}
	return per, boot
}

// monthUsage maps uid → bytes used this calendar month (quota enforcement).
func (p *panel) monthUsage() map[string]uint64 {
	per, _ := parseStats(p.statsPath())
	out := map[string]uint64{}
	for uid, a := range per {
		out[uid] = a.Month
	}
	return out
}

// stats aggregates the server's JSONL accounting log per user.
func (p *panel) stats(w http.ResponseWriter, r *http.Request) {
	per, boot := parseStats(p.statsPath())
	p.mu.Lock()
	users := p.store.Users
	p.mu.Unlock()
	out := map[string]any{"users": map[string]*statAgg{}, "boot": boot}
	m := out["users"].(map[string]*statAgg)
	for _, u := range users {
		if a := per[u.ID]; a != nil {
			m[u.ID] = a
		} else {
			m[u.ID] = &statAgg{}
		}
	}
	writeJSON(w, out)
}

// trafficBucket is one column of the traffic chart.
type trafficBucket struct {
	T    int64  `json:"t"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// trafficSeries folds stats.jsonl close-events into per-hour buckets for the
// last 24h and per-day buckets for the last 30d (totals across users).
func trafficSeries(path string) ([]trafficBucket, []trafficBucket) {
	now := time.Now()
	h0 := now.Truncate(time.Hour).Add(-23 * time.Hour).Unix()
	d0 := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local).AddDate(0, 0, -29).Unix()
	hours := make([]trafficBucket, 24)
	days := make([]trafficBucket, 30)
	for i := range hours {
		hours[i].T = h0 + int64(i)*3600
	}
	for i := range days {
		days[i].T = d0 + int64(i)*86400
	}
	f, err := os.Open(path)
	if err != nil {
		return hours, days
	}
	defer f.Close()
	var rec struct {
		T    int64  `json:"t"`
		Ev   string `json:"ev"`
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	}
	dec := json.NewDecoder(f)
	for {
		if err := dec.Decode(&rec); err != nil {
			break
		}
		if rec.Ev != "close" {
			continue
		}
		if rec.T >= h0 {
			i := int((rec.T - h0) / 3600)
			if i >= 0 && i < 24 {
				hours[i].Up += rec.Up
				hours[i].Down += rec.Down
			}
		}
		if rec.T >= d0 {
			i := int((rec.T - d0) / 86400)
			if i >= 0 && i < 30 {
				days[i].Up += rec.Up
				days[i].Down += rec.Down
			}
		}
	}
	return hours, days
}

// ------------------------------------------------------------------ audit

type auditRec struct {
	T      int64  `json:"t"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// audit appends one admin action to the JSONL audit log.
func (p *panel) audit(r *http.Request, action, detail string) {
	rec := auditRec{T: time.Now().Unix(), Action: action, Detail: detail}
	if r != nil {
		rec.IP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	b, _ := json.Marshal(rec)
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

// auditTail returns the newest n audit records, oldest first.
func auditTail(path string, n int) []auditRec {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]auditRec, 0, len(lines))
	for _, ln := range lines {
		var r auditRec
		if json.Unmarshal([]byte(ln), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// ------------------------------------------------------------------ util

func sh(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
