// Package server implements the optional relay server.
//
// The server is NOT required for the messenger to function.
// Its roles are:
//   1. Offline message storage  – deliver messages to peers that are currently offline
//   2. Group fan-out            – receive a group message once and broadcast to members
//   3. History sync             – new devices can pull message history
//   4. Presence aggregation     – collect online/offline events for all peers
//   5. Media CDN proxy          – cache media blobs to reduce peer upload bandwidth
//   6. User accounts            – register/login, username directory, peer discovery
//
// Architecture:
//   - HTTP/1.1 WebSocket for each client connection
//   - SQLite for message storage (swap for Postgres in production)
//   - In-memory presence map
//   - No business logic in cleartext – messages arrive already encrypted
package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"

	"github.com/secureNqwer/zerolink/core"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// ServerConfig holds relay server settings.
type ServerConfig struct {
	ListenAddr      string        `json:"listen_addr"`
	DBPath          string        `json:"db_path"`
	MediaDir        string        `json:"media_dir"`
	MaxMsgAgeDays   int           `json:"max_msg_age_days"`
	MaxMediaSizeMB  int           `json:"max_media_size_mb"`
	PingInterval    time.Duration `json:"ping_interval"`
	WriteTimeout    time.Duration `json:"write_timeout"`
	ReadTimeout     time.Duration `json:"read_timeout"`
	MaxConnsPerPeer int           `json:"max_conns_per_peer"`
	TLSCertFile     string        `json:"tls_cert,omitempty"`
	TLSKeyFile      string        `json:"tls_key,omitempty"`
	LogLevel        string        `json:"log_level"`
	TokenSecret     string        `json:"token_secret"` // HMAC key for auth tokens
	// ZeroTier (optional – server joins a ZT network so clients can reach it)
	ZTNetwork       string `json:"zt_network,omitempty"`
	ZTPort          uint16 `json:"zt_port,omitempty"`
	ZTDataDir       string `json:"zt_data_dir,omitempty"`
}

// UserAccount represents a registered user on the server.
type UserAccount struct {
	Username    string    `json:"username"`
	PasswordHash string   `json:"-"`
	Salt        string    `json:"-"`
	Nickname    string    `json:"nickname"`
	Bio         string    `json:"bio,omitempty"`
	AvatarPath  string    `json:"avatar_path,omitempty"`
	NodeID      string    `json:"node_id,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:      ":8080",
		DBPath:          "./server.db",
		MediaDir:        "./server-media",
		MaxMsgAgeDays:   30,
		MaxMediaSizeMB:  512,
		PingInterval:    30 * time.Second,
		WriteTimeout:    10 * time.Second,
		ReadTimeout:     60 * time.Second,
		MaxConnsPerPeer: 5,
		LogLevel:        "info",
		TokenSecret:     "change-me-in-production",
		ZTPort:          9993,
		ZTDataDir:       "./zt-server",
	}
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server is the relay server instance.
type Server struct {
	cfg      *ServerConfig
	log      *zap.Logger
	db       *sql.DB
	upgrader websocket.Upgrader

	// connected clients indexed by peerID string
	clients sync.Map // string → []*client

	// presence: peerID string → last seen time
	presence sync.Map

	httpSrv *http.Server
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// client represents one connected WebSocket peer.
type client struct {
	id       string // UUID for this connection
	peerID   core.PeerID
	conn     *websocket.Conn
	sendCh   chan *core.RelayFrame
	srv      *Server
	mu       sync.Mutex
	authed   bool
	username string // linked user account (if authenticated with token)
}

// ─── Constructor / Start / Stop ───────────────────────────────────────────────

// NewServer creates a relay server.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}
	log, err := buildServerLogger(cfg.LogLevel)
	if err != nil {
		return nil, err
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("server: db: %w", err)
	}
	if err := os.MkdirAll(cfg.MediaDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		log:    log,
		db:     db,
		stopCh: make(chan struct{}),
		upgrader: websocket.Upgrader{
			CheckOrigin:     func(r *http.Request) bool { return true },
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
		},
	}
	return s, nil
}

// Start begins serving WebSocket connections.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", s.handleWSUpgrade)
	mux.HandleFunc("/media/", s.handleMedia)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/auth/register", s.handleHTTPRegister)
	mux.HandleFunc("/auth/login", s.handleHTTPLogin)
	mux.HandleFunc("/peers", s.handleHTTPPeers)

	s.httpSrv = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  s.cfg.ReadTimeout + 5*time.Second,
		WriteTimeout: s.cfg.WriteTimeout + 5*time.Second,
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}

	// Background tasks
	s.wg.Add(2)
	go s.pruneLoop()
	go s.pingLoop()

	s.log.Info("relay server listening", zap.String("addr", s.cfg.ListenAddr))

	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		return s.httpSrv.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}
	return s.httpSrv.Serve(ln)
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	close(s.stopCh)
	err := s.httpSrv.Shutdown(ctx)
	s.wg.Wait()
	s.db.Close()
	return err
}

// ─── WebSocket upgrade ────────────────────────────────────────────────────────

func (s *Server) handleWSUpgrade(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("ws upgrade failed", zap.Error(err))
		return
	}
	c := &client{
		id:     uuid.New().String(),
		conn:   conn,
		sendCh: make(chan *core.RelayFrame, 256),
		srv:    s,
	}
	s.wg.Add(2)
	go c.writePump()
	go c.readPump()
}

// ─── Client read pump ─────────────────────────────────────────────────────────

func (c *client) readPump() {
	defer func() {
		c.srv.wg.Done()
		c.srv.unregister(c)
		c.conn.Close()
	}()
	c.conn.SetReadDeadline(time.Now().Add(c.srv.cfg.ReadTimeout))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(c.srv.cfg.ReadTimeout))
		return nil
	})
	for {
		var frame core.RelayFrame
		if err := c.conn.ReadJSON(&frame); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				c.srv.log.Debug("client read error", zap.String("client", c.id), zap.Error(err))
			}
			return
		}
		c.conn.SetReadDeadline(time.Now().Add(c.srv.cfg.ReadTimeout))
		c.srv.handleFrame(c, &frame)
	}
}

// ─── Client write pump ────────────────────────────────────────────────────────

func (c *client) writePump() {
	defer c.srv.wg.Done()
	ticker := time.NewTicker(c.srv.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case frame, ok := <-c.sendCh:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(c.srv.cfg.WriteTimeout))
			if err := c.conn.WriteJSON(frame); err != nil {
				c.srv.log.Warn("client write error", zap.Error(err))
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-c.srv.stopCh:
			return
		}
	}
}

	// ─── Frame routing ────────────────────────────────────────────────────────────

func (s *Server) handleFrame(c *client, frame *core.RelayFrame) {
	// Allow auth, register, login without prior auth
	if !c.authed && frame.Cmd != core.CmdAuth &&
		frame.Cmd != core.CmdRegister &&
		frame.Cmd != core.CmdLogin {
		c.send(&core.RelayFrame{
			Cmd:     core.CmdError,
			Payload: jsonStr("not authenticated"),
		})
		return
	}

	switch frame.Cmd {
	case core.CmdAuth:
		s.handleAuth(c, frame)
	case core.CmdRegister:
		s.handleRegister(c, frame)
	case core.CmdLogin:
		s.handleLogin(c, frame)
	case core.CmdRelay:
		s.handleRelay(c, frame)
	case core.CmdSync:
		s.handleSync(c, frame)
	case core.CmdPresence:
		s.handlePresence(c, frame)
	case core.CmdListPeers:
		s.handleListPeers(c, frame)
	case core.CmdUpdateProfile:
		s.handleUpdateProfile(c, frame)
	case core.CmdHandshake, core.CmdHandshakeAck:
		s.handleHandshakeRelay(c, frame)
	case core.CmdPing:
		c.send(&core.RelayFrame{Cmd: core.CmdPong, Timestamp: time.Now().UnixNano()})
	default:
		s.log.Warn("unknown relay command", zap.String("cmd", string(frame.Cmd)))
	}
}

// AuthPayloadWithUser extends the relay auth with optional username/token.
type AuthPayloadWithUser struct {
	core.AuthPayload
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
}

// handleAuth validates the client's identity and registers it.
func (s *Server) handleAuth(c *client, frame *core.RelayFrame) {
	var auth AuthPayloadWithUser
	if err := json.Unmarshal(frame.Payload, &auth); err != nil {
		c.send(errFrame("invalid auth payload"))
		return
	}

	// Basic timestamp freshness check (±5 min)
	diff := time.Since(time.Unix(0, auth.Timestamp))
	if diff < -5*time.Minute || diff > 5*time.Minute {
		c.send(errFrame("auth timestamp out of range"))
		return
	}

	// If username+token provided, validate against user accounts
	if auth.Username != "" && auth.Token != "" {
		user, err := s.getUserByUsername(auth.Username)
		if err != nil || user == nil {
			c.send(errFrame("user not found"))
			return
		}
		if !s.validateToken(user, auth.Token) {
			c.send(errFrame("invalid token"))
			return
		}
		// Update node binding
		s.db.Exec(`UPDATE users SET node_id = ?, fingerprint = ? WHERE username = ?`,
			auth.NodeID, auth.Fingerprint, auth.Username)
		c.username = auth.Username
	}

	c.mu.Lock()
	c.peerID = core.PeerID{
		NodeID:      core.NodeID(auth.NodeID),
		Fingerprint: auth.Fingerprint,
	}
	c.authed = true
	c.mu.Unlock()

	s.register(c)
	s.presence.Store(c.peerID.String(), time.Now())

	c.send(&core.RelayFrame{Cmd: core.CmdAuthOK, Timestamp: time.Now().UnixNano()})
	s.log.Info("client authenticated",
		zap.String("node", auth.NodeID),
		zap.String("fp", auth.Fingerprint),
		zap.String("user", c.username),
	)

	// Deliver any stored offline messages
	s.deliverOffline(c)
}

// handleRegister processes a registration request.
func (s *Server) handleRegister(c *client, frame *core.RelayFrame) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Nickname   string `json:"nickname"`
		Bio        string `json:"bio"`
		AvatarPath string `json:"avatar_path"`
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		c.send(errFrame("invalid register payload"))
		return
	}

	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	if !isValidUsername(req.Username) {
		c.send(errFrame("invalid username: use 3-32 english letters, digits, underscores"))
		return
	}
	if len(req.Password) < 4 {
		c.send(errFrame("password must be at least 4 characters"))
		return
	}

	// Check if username exists (case-insensitive)
	existing, _ := s.getUserByUsername(req.Username)
	if existing != nil {
		c.send(errFrame("username already taken"))
		return
	}

	hash, salt := hashPassword(req.Password)
	now := time.Now()
	_, err := s.db.Exec(`
		INSERT INTO users (username, password_hash, salt, nickname, bio, avatar_path, created_at, last_login)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Username, hash, salt, req.Nickname, req.Bio, req.AvatarPath, now.UnixNano(), now.UnixNano())
	if err != nil {
		s.log.Error("register insert", zap.Error(err))
		c.send(errFrame("registration failed"))
		return
	}

	user := &UserAccount{
		Username: req.Username, Nickname: req.Nickname,
		Bio: req.Bio, AvatarPath: req.AvatarPath,
		CreatedAt: now, LastLogin: now,
	}
	token := s.generateToken(user)

	c.send(&core.RelayFrame{
		Cmd: core.CmdAuthOK,
		Payload: jsonMsg(map[string]string{
			"ok":       "true",
			"message":  "registered",
			"token":    token,
			"username": req.Username,
		}),
		Timestamp: time.Now().UnixNano(),
	})
	s.log.Info("user registered", zap.String("username", req.Username))
}

// handleLogin processes a login request.
func (s *Server) handleLogin(c *client, frame *core.RelayFrame) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		c.send(errFrame("invalid login payload"))
		return
	}

	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	user, err := s.getUserByUsername(req.Username)
	if err != nil || user == nil {
		c.send(errFrame("invalid username or password"))
		return
	}

	if !checkPassword(user.PasswordHash, user.Salt, req.Password) {
		c.send(errFrame("invalid username or password"))
		return
	}

	// Update last login
	s.db.Exec(`UPDATE users SET last_login = ? WHERE username = ?`,
		time.Now().UnixNano(), req.Username)

	token := s.generateToken(user)

	c.send(&core.RelayFrame{
		Cmd: core.CmdAuthOK,
		Payload: jsonMsg(map[string]string{
			"ok":          "true",
			"message":     "logged in",
			"token":       token,
			"username":    user.Username,
			"nickname":    user.Nickname,
			"bio":         user.Bio,
			"avatar_path": user.AvatarPath,
		}),
		Timestamp: time.Now().UnixNano(),
	})
	s.log.Info("user logged in", zap.String("username", req.Username))
}

// handleListPeers returns all registered users that have a node_id associated.
func (s *Server) handleListPeers(c *client, frame *core.RelayFrame) {
	rows, err := s.db.Query(`
		SELECT username, nickname, bio, avatar_path, node_id, fingerprint, last_login
		FROM users WHERE node_id != '' AND node_id IS NOT NULL
		ORDER BY last_login DESC`)
	if err != nil {
		c.send(errFrame("query failed"))
		return
	}
	defer rows.Close()

	type peerInfo struct {
		Username    string `json:"username"`
		Nickname    string `json:"nickname"`
		Bio         string `json:"bio,omitempty"`
		AvatarPath  string `json:"avatar_path,omitempty"`
		NodeID      string `json:"node_id"`
		Fingerprint string `json:"fingerprint"`
		Online      bool   `json:"online"`
		LastLogin   int64  `json:"last_login"`
	}
	var peers []peerInfo
	for rows.Next() {
		var p peerInfo
		var lastLogin int64
		if err := rows.Scan(&p.Username, &p.Nickname, &p.Bio, &p.AvatarPath,
			&p.NodeID, &p.Fingerprint, &lastLogin); err != nil {
			continue
		}
		// Check if online
		peerKey := fmt.Sprintf("%s:%s", p.NodeID, p.Fingerprint)
		_, online := s.clients.Load(peerKey)
		p.Online = online
		p.LastLogin = lastLogin
		peers = append(peers, p)
	}

	payload, _ := json.Marshal(peers)
	c.send(&core.RelayFrame{
		Cmd:       core.CmdListPeers,
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
	})
}

// handleHandshakeRelay forwards a handshake frame to the target peer.
func (s *Server) handleHandshakeRelay(c *client, frame *core.RelayFrame) {
	to := core.NodeID(frame.PeerID)
	if to == "" {
		return
	}
	// Forward to all connected clients with that node ID
	s.clients.Range(func(_, v interface{}) bool {
		for _, cl := range v.([]*client) {
			if cl.peerID.NodeID == to && cl.id != c.id {
				cl.send(frame)
			}
		}
		return true
	})
}

// handleUpdateProfile updates the user's nickname/bio/avatar.
func (s *Server) handleUpdateProfile(c *client, frame *core.RelayFrame) {
	if c.username == "" {
		c.send(errFrame("no user account linked"))
		return
	}
	var req struct {
		Nickname   string `json:"nickname"`
		Bio        string `json:"bio"`
		AvatarPath string `json:"avatar_path"`
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		c.send(errFrame("invalid payload"))
		return
	}
	_, err := s.db.Exec(`UPDATE users SET nickname = ?, bio = ?, avatar_path = ? WHERE username = ?`,
		req.Nickname, req.Bio, req.AvatarPath, c.username)
	if err != nil {
		c.send(errFrame("update failed"))
		return
	}
	c.send(&core.RelayFrame{
		Cmd: core.CmdAuthOK,
		Payload: jsonMsg(map[string]string{
			"ok":      "true",
			"message": "profile updated",
		}),
		Timestamp: time.Now().UnixNano(),
	})
}

// ─── User account helpers ─────────────────────────────────────────────────────

func (s *Server) getUserByUsername(username string) (*UserAccount, error) {
	row := s.db.QueryRow(`
		SELECT username, password_hash, salt, nickname, bio, avatar_path,
		       node_id, fingerprint, created_at, last_login
		FROM users WHERE username = ?`, username)
	var u UserAccount
	var createdAt, lastLogin int64
	var nodeID, fingerprint sql.NullString
	err := row.Scan(&u.Username, &u.PasswordHash, &u.Salt, &u.Nickname,
		&u.Bio, &u.AvatarPath, &nodeID, &fingerprint, &createdAt, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = time.Unix(0, createdAt)
	u.LastLogin = time.Unix(0, lastLogin)
	if nodeID.Valid {
		u.NodeID = nodeID.String
	}
	if fingerprint.Valid {
		u.Fingerprint = fingerprint.String
	}
	return &u, nil
}

func (s *Server) generateToken(user *UserAccount) string {
	data := fmt.Sprintf("%s:%d:%s", user.Username, user.CreatedAt.UnixNano(), s.cfg.TokenSecret)
	mac := hmac.New(sha256.New, []byte(s.cfg.TokenSecret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) validateToken(user *UserAccount, token string) bool {
	expected := s.generateToken(user)
	return hmac.Equal([]byte(expected), []byte(token))
}

// ─── Password helpers ─────────────────────────────────────────────────────────

func hashPassword(password string) (hash, salt string) {
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt = hex.EncodeToString(saltBytes)
	h := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(h[:]), salt
}

func checkPassword(storedHash, salt, password string) bool {
	h := sha256.Sum256([]byte(salt + password))
	return storedHash == hex.EncodeToString(h[:])
}

func isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

// handleRelay stores and/or fans out a message.
func (s *Server) handleRelay(c *client, frame *core.RelayFrame) {
	var msg core.Message
	if err := json.Unmarshal(frame.Payload, &msg); err != nil {
		c.send(errFrame("bad relay payload"))
		return
	}
	if string(msg.ID) == "" {
		c.send(errFrame("missing message ID"))
		return
	}

	// Persist for offline delivery
	if err := s.storeMessage(frame.Payload); err != nil {
		s.log.Error("store message failed", zap.Error(err))
	}

	// Fan-out: deliver to all online members of the chat
	chat, err := s.loadChat(msg.ChatID)
	if err != nil || chat == nil {
		// Can't look up chat members – just try direct delivery to recipient
		if msg.RecipientID != nil {
			s.deliverTo(*msg.RecipientID, frame)
		}
		return
	}

	for _, member := range chat.Members {
		if member.PeerID.String() == c.peerID.String() {
			continue // don't echo back to sender
		}
		s.deliverTo(member.PeerID, frame)
	}
}

// handleSync returns stored messages newer than the requested timestamp.
func (s *Server) handleSync(c *client, frame *core.RelayFrame) {
	var req struct {
		ChatID  string `json:"chat_id"`
		AfterTS int64  `json:"after_ts"`
	}
	if err := json.Unmarshal(frame.Payload, &req); err != nil {
		c.send(errFrame("bad sync request"))
		return
	}

	rows, err := s.db.Query(`
		SELECT payload FROM messages
		WHERE chat_id = ? AND sent_at > ?
		ORDER BY sent_at ASC LIMIT 500`,
		req.ChatID, req.AfterTS)
	if err != nil {
		c.send(errFrame("sync query failed"))
		return
	}
	defer rows.Close()

	var msgs []json.RawMessage
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		msgs = append(msgs, json.RawMessage(raw))
	}

	respPayload, _ := json.Marshal(msgs)
	c.send(&core.RelayFrame{
		Cmd:       core.CmdSyncResp,
		ID:        frame.ID,
		Payload:   respPayload,
		Timestamp: time.Now().UnixNano(),
	})
}

func (s *Server) handlePresence(c *client, frame *core.RelayFrame) {
	s.presence.Store(c.peerID.String(), time.Now())
}

// ─── Media upload / download ──────────────────────────────────────────────────

func (s *Server) handleMedia(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Path[len("/media/"):]
	if hash == "" {
		http.Error(w, "missing hash", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		path := s.mediaPath(hash)
		http.ServeFile(w, r, path)

	case http.MethodPut:
		maxSize := int64(s.cfg.MaxMediaSizeMB) << 20
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)
		data := make([]byte, 0, 4096)
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Body.Read(buf)
			data = append(data, buf[:n]...)
			if err != nil {
				break
			}
		}
		path := s.mediaPath(hash)
		os.MkdirAll(path[:len(path)-len(hash)-1], 0o700)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) mediaPath(hash string) string {
	if len(hash) < 4 {
		return s.cfg.MediaDir + "/" + hash
	}
	return fmt.Sprintf("%s/%s/%s/%s", s.cfg.MediaDir, hash[:2], hash[2:4], hash)
}

// ─── HTTP Auth endpoints ─────────────────────────────────────────────────────

// handleHTTPRegister handles POST /auth/register
func (s *Server) handleHTTPRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Nickname   string `json:"nickname"`
		Bio        string `json:"bio"`
		AvatarPath string `json:"avatar_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "bad request"})
		return
	}
	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	if !isValidUsername(req.Username) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid username"})
		return
	}
	if len(req.Password) < 4 {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "password too short"})
		return
	}
	existing, _ := s.getUserByUsername(req.Username)
	if existing != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "username taken"})
		return
	}
	hash, salt := hashPassword(req.Password)
	now := time.Now().UnixNano()
	_, err := s.db.Exec(`
		INSERT INTO users (username, password_hash, salt, nickname, bio, avatar_path, created_at, last_login)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Username, hash, salt, req.Nickname, req.Bio, req.AvatarPath, now, now)
	if err != nil {
		s.log.Error("register", zap.Error(err))
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "registration failed"})
		return
	}
	user := &UserAccount{
		Username: req.Username, Nickname: req.Nickname,
		Bio: req.Bio, AvatarPath: req.AvatarPath,
		CreatedAt: time.Unix(0, now), LastLogin: time.Unix(0, now),
	}
	token := s.generateToken(user)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "token": token, "username": req.Username,
	})
}

// handleHTTPLogin handles POST /auth/login
func (s *Server) handleHTTPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "bad request"})
		return
	}
	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	user, err := s.getUserByUsername(req.Username)
	if err != nil || user == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid credentials"})
		return
	}
	if !checkPassword(user.PasswordHash, user.Salt, req.Password) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid credentials"})
		return
	}
	s.db.Exec(`UPDATE users SET last_login = ? WHERE username = ?`, time.Now().UnixNano(), req.Username)
	token := s.generateToken(user)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok": true, "token": token, "username": user.Username,
		"nickname": user.Nickname, "bio": user.Bio,
	})
}

// handleHTTPPeers handles GET /peers
func (s *Server) handleHTTPPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.db.Query(`
		SELECT username, nickname, bio, avatar_path, node_id, fingerprint, last_login
		FROM users WHERE node_id != '' AND node_id IS NOT NULL
		ORDER BY last_login DESC`)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type peerInfo struct {
		Username    string `json:"username"`
		Nickname    string `json:"nickname"`
		Bio         string `json:"bio,omitempty"`
		AvatarPath  string `json:"avatar_path,omitempty"`
		NodeID      string `json:"node_id"`
		Fingerprint string `json:"fingerprint"`
		Online      bool   `json:"online"`
	}
	var peers []peerInfo
	for rows.Next() {
		var p peerInfo
		var lastLogin int64
		if err := rows.Scan(&p.Username, &p.Nickname, &p.Bio, &p.AvatarPath,
			&p.NodeID, &p.Fingerprint, &lastLogin); err != nil {
			continue
		}
		peerKey := fmt.Sprintf("%s:%s", p.NodeID, p.Fingerprint)
		_, online := s.clients.Load(peerKey)
		p.Online = online
		peers = append(peers, p)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "peers": peers})
}

// ─── Client registry ──────────────────────────────────────────────────────────

func (s *Server) register(c *client) {
	key := c.peerID.String()
	existing, _ := s.clients.LoadOrStore(key, []*client{c})
	if conns, ok := existing.([]*client); ok {
		// Check if already stored (LoadOrStore returns existing on contention)
		for _, existing := range conns {
			if existing.id == c.id {
				return
			}
		}
		s.clients.Store(key, append(conns, c))
	}
}

func (s *Server) unregister(c *client) {
	key := c.peerID.String()
	v, ok := s.clients.Load(key)
	if !ok {
		return
	}
	conns := v.([]*client)
	filtered := conns[:0]
	for _, conn := range conns {
		if conn.id != c.id {
			filtered = append(filtered, conn)
		}
	}
	if len(filtered) == 0 {
		s.clients.Delete(key)
		s.presence.Store(key, time.Now()) // record last-seen
	} else {
		s.clients.Store(key, filtered)
	}
}

func (s *Server) deliverTo(peer core.PeerID, frame *core.RelayFrame) {
	v, ok := s.clients.Load(peer.String())
	if !ok {
		return // peer offline – message is already persisted
	}
	for _, c := range v.([]*client) {
		c.send(frame)
	}
}

func (c *client) send(frame *core.RelayFrame) {
	select {
	case c.sendCh <- frame:
	default:
		c.srv.log.Warn("client send buffer full", zap.String("peer", c.peerID.String()))
	}
}

// ─── Offline delivery ─────────────────────────────────────────────────────────

func (s *Server) deliverOffline(c *client) {
	rows, err := s.db.Query(`
		SELECT id, payload FROM messages
		WHERE recipient_peer_id = ? AND delivered = 0
		ORDER BY sent_at ASC LIMIT 200`,
		c.peerID.String())
	if err != nil {
		return
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		var payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			continue
		}
		ids = append(ids, id)
		c.send(&core.RelayFrame{
			Cmd:       core.CmdRelay,
			Payload:   json.RawMessage(payload),
			Timestamp: time.Now().UnixNano(),
		})
	}
	rows.Close()

	// Mark as delivered
	if len(ids) > 0 {
		for _, id := range ids {
			s.db.Exec(`UPDATE messages SET delivered = 1 WHERE id = ?`, id)
		}
		s.log.Info("delivered offline messages",
			zap.String("peer", c.peerID.String()),
			zap.Int("count", len(ids)),
		)
	}
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func (s *Server) storeMessage(raw json.RawMessage) error {
	var msg core.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return err
	}
	recipID := ""
	if msg.RecipientID != nil {
		recipID = msg.RecipientID.String()
	}
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO messages
			(id, chat_id, sender_peer_id, recipient_peer_id, sent_at, payload, delivered)
		VALUES (?,?,?,?,?,?,0)`,
		string(msg.ID),
		string(msg.ChatID),
		msg.SenderID.String(),
		recipID,
		msg.SentAt.UnixNano(),
		[]byte(raw),
	)
	return err
}

func (s *Server) loadChat(chatID core.ChatID) (*core.Chat, error) {
	row := s.db.QueryRow(`SELECT payload FROM chats WHERE id = ?`, string(chatID))
	var raw []byte
	if err := row.Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var chat core.Chat
	return &chat, json.Unmarshal(raw, &chat)
}

// UpsertChat stores or updates a chat definition.
// Clients should call this after creating a group so the server can do fan-out.
func (s *Server) UpsertChat(chat *core.Chat) error {
	raw, _ := json.Marshal(chat)
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO chats (id, payload, updated_at) VALUES (?,?,?)`,
		string(chat.ID), raw, time.Now().UnixNano())
	return err
}

// ─── Background tasks ─────────────────────────────────────────────────────────

func (s *Server) pruneLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().AddDate(0, 0, -s.cfg.MaxMsgAgeDays).UnixNano()
			res, err := s.db.Exec(`DELETE FROM messages WHERE sent_at < ?`, cutoff)
			if err == nil {
				n, _ := res.RowsAffected()
				if n > 0 {
					s.log.Info("pruned old messages", zap.Int64("count", n))
				}
			}
		}
	}
}

func (s *Server) pingLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			frame := &core.RelayFrame{
				Cmd:       core.CmdPing,
				Timestamp: time.Now().UnixNano(),
			}
			s.clients.Range(func(_, v interface{}) bool {
				for _, c := range v.([]*client) {
					c.send(frame)
				}
				return true
			})
		}
	}
}

// ─── DB setup ─────────────────────────────────────────────────────────────────

func openDB(path string) (*sql.DB, error) {
	os.MkdirAll(path[:max(0, len(path)-len("/server.db"))], 0o700)
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=on", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS messages (
			id                TEXT PRIMARY KEY,
			chat_id           TEXT NOT NULL,
			sender_peer_id    TEXT NOT NULL,
			recipient_peer_id TEXT,
			sent_at           INTEGER NOT NULL,
			payload           BLOB NOT NULL,
			delivered         INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_peer_id, delivered, sent_at)`,
		`CREATE INDEX IF NOT EXISTS idx_msg_chat      ON messages(chat_id, sent_at)`,

		`CREATE TABLE IF NOT EXISTS chats (
			id         TEXT PRIMARY KEY,
			payload    BLOB NOT NULL,
			updated_at INTEGER NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS peers (
			peer_id    TEXT PRIMARY KEY,
			last_seen  INTEGER NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS users (
			username      TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			salt          TEXT NOT NULL,
			nickname      TEXT NOT NULL DEFAULT '',
			bio           TEXT NOT NULL DEFAULT '',
			avatar_path   TEXT NOT NULL DEFAULT '',
			node_id       TEXT NOT NULL DEFAULT '',
			fingerprint   TEXT NOT NULL DEFAULT '',
			created_at    INTEGER NOT NULL,
			last_login    INTEGER NOT NULL
		)`,
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return nil, fmt.Errorf("server db migrate: %w", err)
		}
	}
	return db, tx.Commit()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func jsonStr(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

func jsonMsg(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func errFrame(msg string) *core.RelayFrame {
	return &core.RelayFrame{
		Cmd:       core.CmdError,
		Payload:   jsonStr(msg),
		Timestamp: time.Now().UnixNano(),
	}
}

func buildServerLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	switch level {
	case "info":
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	}
	return cfg.Build()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
