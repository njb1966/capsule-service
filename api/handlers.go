package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"gemcities.com/capsule-service/auth"
	"gemcities.com/capsule-service/config"
	"gemcities.com/capsule-service/email"
	"gemcities.com/capsule-service/files"
)

type Server struct {
	db      *sql.DB
	cfg     *config.Config
	mailer  *email.Sender
	files   *files.Manager
	logger  *log.Logger
}

func NewServer(db *sql.DB, cfg *config.Config, mailer *email.Sender, fm *files.Manager, logger *log.Logger) *Server {
	return &Server{db: db, cfg: cfg, mailer: mailer, files: fm, logger: logger}
}

func (s *Server) Routes() http.Handler {
	authRL  := newRateLimiter(5)  // 5 req/min for auth endpoints
	fileRL  := newRateLimiter(60) // 60 req/min for file endpoints

	mux := http.NewServeMux()

	// Public auth endpoints
	mux.HandleFunc("POST /api/register",              authRL.middleware(s.handleRegister))
	mux.HandleFunc("POST /api/verify-email",          authRL.middleware(s.handleVerifyEmail))
	mux.HandleFunc("POST /api/login",                 authRL.middleware(s.handleLogin))
	mux.HandleFunc("POST /api/logout",                s.handleLogout)
	mux.HandleFunc("POST /api/password-reset-request", authRL.middleware(s.handlePasswordResetRequest))
	mux.HandleFunc("POST /api/password-reset",        authRL.middleware(s.handlePasswordReset))

	// Authenticated file endpoints
	requireAuth := auth.Middleware(s.cfg.Auth.JWTSecret)
	mux.Handle("GET /api/files",          requireAuth(fileRL.middleware(http.HandlerFunc(s.handleFileList))))
	mux.Handle("GET /api/files/",         requireAuth(fileRL.middleware(http.HandlerFunc(s.handleFileRead))))
	mux.Handle("PUT /api/files/",         requireAuth(fileRL.middleware(http.HandlerFunc(s.handleFileWrite))))
	mux.Handle("DELETE /api/files/",      requireAuth(fileRL.middleware(http.HandlerFunc(s.handleFileDelete))))
	mux.Handle("POST /api/files/rename",  requireAuth(fileRL.middleware(http.HandlerFunc(s.handleFileRename))))
	mux.Handle("POST /api/files/mkdir",   requireAuth(fileRL.middleware(http.HandlerFunc(s.handleMkdir))))
	mux.Handle("GET /api/account",        requireAuth(fileRL.middleware(http.HandlerFunc(s.handleGetAccount))))
	mux.Handle("GET /api/export",         requireAuth(http.HandlerFunc(s.handleExport)))
	mux.Handle("DELETE /api/account",     requireAuth(authRL.middleware(s.handleDeleteAccount)))

	s.registerAdminRoutes(mux)
	return mux
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(v)
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// --- auth handlers ---

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.Email    = strings.ToLower(strings.TrimSpace(req.Email))

	if err := auth.ValidateUsername(req.Username); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_USERNAME"); return
	}
	if !emailRe.MatchString(req.Email) {
		writeErr(w, http.StatusBadRequest, "INVALID_EMAIL"); return
	}
	if len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT"); return
	}

	hash, err := auth.HashPassword(req.Password, s.cfg.Auth.BcryptCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	res, err := s.db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES (?,?,?)`,
		req.Username, req.Email, hash)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE") && strings.Contains(msg, "username") {
			writeErr(w, http.StatusConflict, "USERNAME_TAKEN"); return
		}
		if strings.Contains(msg, "UNIQUE") && strings.Contains(msg, "email") {
			writeErr(w, http.StatusConflict, "EMAIL_TAKEN"); return
		}
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	userID, _ := res.LastInsertId()

	plain, hashed, err := auth.GenerateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}
	expiry := time.Now().Add(24 * time.Hour)
	if err := auth.StoreVerificationToken(s.db, userID, hashed, expiry); err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	go func() {
		if err := s.mailer.SendVerification(req.Email, req.Username, plain, s.cfg.Server.Domain); err != nil {
			s.logger.Printf("send verification email: %v", err)
		}
	}()

	writeJSON(w, http.StatusCreated, map[string]string{"status": "VERIFY_EMAIL"})
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct{ Token string `json:"token"` }
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}

	hashed := auth.HashToken(req.Token)
	var userID int64
	var username string
	var expires int64
	err := s.db.QueryRow(
		`SELECT ev.user_id, u.username, ev.expires_at
		 FROM email_verifications ev JOIN users u ON u.id=ev.user_id
		 WHERE ev.token_hash=? AND ev.used=0`, hashed).
		Scan(&userID, &username, &expires)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_TOKEN"); return
	}
	if time.Now().Unix() > expires {
		writeErr(w, http.StatusBadRequest, "TOKEN_EXPIRED"); return
	}

	tx, _ := s.db.Begin()
	tx.Exec(`UPDATE users SET email_verified=1 WHERE id=?`, userID)
	tx.Exec(`UPDATE email_verifications SET used=1 WHERE token_hash=?`, hashed)
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	// Provision capsule
	if err := s.files.InitCapsule(username); err != nil {
		s.logger.Printf("init capsule for %s: %v", username, err)
	} else {
		go s.addAgateHost(username)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "VERIFIED"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}

	var userID int64
	var username, hash string
	var verified int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, email_verified FROM users WHERE email=?`,
		strings.ToLower(strings.TrimSpace(req.Email))).
		Scan(&userID, &username, &hash, &verified)
	if err == sql.ErrNoRows || !auth.CheckPassword(hash, req.Password) {
		writeErr(w, http.StatusUnauthorized, "INVALID_CREDENTIALS"); return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}
	if verified == 0 {
		writeErr(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED"); return
	}

	token, err := auth.IssueJWT(userID, username, s.cfg.Auth.JWTSecret, s.cfg.Auth.SessionDurationDays)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	auth.SetSessionCookie(w, token, s.cfg.Auth.SessionDurationDays)
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email string `json:"email"` }
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}

	// Always return the same response regardless of whether email exists
	var userID int64
	err := s.db.QueryRow(`SELECT id FROM users WHERE email=?`,
		strings.ToLower(strings.TrimSpace(req.Email))).Scan(&userID)

	if err == nil {
		plain, hashed, genErr := auth.GenerateToken()
		if genErr == nil {
			expiry := time.Now().Add(1 * time.Hour)
			if storeErr := auth.StoreResetToken(s.db, userID, hashed, expiry); storeErr == nil {
				go func() {
					if err := s.mailer.SendPasswordReset(req.Email, plain, s.cfg.Server.Domain); err != nil {
						s.logger.Printf("send reset email: %v", err)
					}
				}()
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}
	if len(req.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT"); return
	}

	hashed := auth.HashToken(req.Token)
	var userID int64
	var expires int64
	err := s.db.QueryRow(
		`SELECT user_id, expires_at FROM password_reset_tokens WHERE token_hash=? AND used=0`,
		hashed).Scan(&userID, &expires)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_TOKEN"); return
	}
	if time.Now().Unix() > expires {
		writeErr(w, http.StatusBadRequest, "TOKEN_EXPIRED"); return
	}

	hash, err := auth.HashPassword(req.Password, s.cfg.Auth.BcryptCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	tx, _ := s.db.Begin()
	tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, userID)
	tx.Exec(`UPDATE password_reset_tokens SET used=1 WHERE token_hash=?`, hashed)
	tx.Commit()

	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

// --- file handlers ---

func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	path := r.URL.Query().Get("path")
	list, err := s.files.List(claims.Username, path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "NOT_FOUND"); return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleFileRead(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	relPath := strings.TrimPrefix(r.URL.Path, "/api/files/")
	data, err := s.files.Read(claims.Username, relPath)
	if err != nil {
		writeErr(w, http.StatusNotFound, "NOT_FOUND"); return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleFileWrite(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	relPath := strings.TrimPrefix(r.URL.Path, "/api/files/")

	data, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.Limits.MaxFileSizeBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}
	if int64(len(data)) > s.cfg.Limits.MaxFileSizeBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE"); return
	}

	var currentStorage int64
	s.db.QueryRow(`SELECT storage_bytes FROM users WHERE id=?`, claims.UserID).Scan(&currentStorage)

	newTotal, err := s.files.Write(claims.Username, relPath, data, currentStorage)
	if err != nil {
		if strings.Contains(err.Error(), "limit") {
			writeErr(w, http.StatusForbidden, "LIMIT_EXCEEDED"); return
		}
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}

	s.db.Exec(`UPDATE users SET storage_bytes=? WHERE id=?`, newTotal, claims.UserID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	relPath := strings.TrimPrefix(r.URL.Path, "/api/files/")

	var currentStorage int64
	s.db.QueryRow(`SELECT storage_bytes FROM users WHERE id=?`, claims.UserID).Scan(&currentStorage)

	newTotal, err := s.files.Delete(claims.Username, relPath, currentStorage)
	if err != nil {
		writeErr(w, http.StatusNotFound, "NOT_FOUND"); return
	}
	s.db.Exec(`UPDATE users SET storage_bytes=? WHERE id=?`, newTotal, claims.UserID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleFileRename(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	var req struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}
	if err := s.files.Rename(claims.Username, req.OldPath, req.NewPath); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error()); return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleMkdir(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	var req struct{ Path string `json:"path"` }
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}
	if err := s.files.Mkdir(claims.Username, req.Path); err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR"); return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	var storageBytes int64
	s.db.QueryRow(`SELECT storage_bytes FROM users WHERE id=?`, claims.UserID).Scan(&storageBytes)
	writeJSON(w, http.StatusOK, map[string]int64{
		"storage_bytes":       storageBytes,
		"storage_limit_bytes": s.cfg.Limits.MaxTotalStorageBytes,
	})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-capsule.zip"`, claims.Username))
	if err := s.files.Export(claims.Username, w); err != nil {
		s.logger.Printf("export for %s: %v", claims.Username, err)
	}
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)

	// Require password confirmation
	var req struct{ Password string `json:"password"` }
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST"); return
	}
	var hash string
	s.db.QueryRow(`SELECT password_hash FROM users WHERE id=?`, claims.UserID).Scan(&hash)
	if !auth.CheckPassword(hash, req.Password) {
		writeErr(w, http.StatusUnauthorized, "INVALID_CREDENTIALS"); return
	}

	if err := s.files.DeleteAll(claims.Username); err != nil {
		s.logger.Printf("delete files for %s: %v", claims.Username, err)
	}
	s.db.Exec(`DELETE FROM users WHERE id=?`, claims.UserID)
	go s.removeAgateHost(claims.Username)

	auth.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

// --- Agate integration ---

func (s *Server) addAgateHost(username string) {
	hostname := username + "." + s.cfg.Server.Domain
	hostnamesFile := "/etc/capsule-service/agate-hostnames"

	// Generate a self-signed cert for this hostname if one doesn't exist
	certDir := "/etc/agate/certs/" + hostname
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		if err := os.MkdirAll(certDir, 0755); err != nil {
			s.logger.Printf("create cert dir for %s: %v", hostname, err)
		} else {
			cmd := exec.Command("bash", "-c",
				"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 "+
					"-keyout /tmp/gemcities_key.pem -out /tmp/gemcities_cert.pem -days 3650 -nodes "+
					"-subj '/CN="+hostname+"' 2>/dev/null && "+
					"openssl x509 -in /tmp/gemcities_cert.pem -outform DER -out "+certDir+"/cert.der && "+
					"openssl ec -in /tmp/gemcities_key.pem -outform DER -out "+certDir+"/key.der 2>/dev/null && "+
					"chmod 600 "+certDir+"/key.der && "+
					"rm -f /tmp/gemcities_key.pem /tmp/gemcities_cert.pem")
			if err := cmd.Run(); err != nil {
				s.logger.Printf("generate cert for %s: %v", hostname, err)
			}
		}
	}

	data, err := os.ReadFile(hostnamesFile)
	if err != nil {
		s.logger.Printf("read agate-hostnames: %v", err)
		return
	}
	current := strings.TrimSpace(string(data))
	// Strip the AGATE_HOSTNAMES= prefix
	current = strings.TrimPrefix(current, `AGATE_HOSTNAMES=`)
	current = strings.Trim(current, `"`)

	hosts := strings.Fields(current)
	for _, h := range hosts {
		if h == hostname {
			return // already present
		}
	}
	hosts = append(hosts, hostname)
	newContent := fmt.Sprintf("AGATE_HOSTNAMES=\"%s\"\n", strings.Join(hosts, " "))
	if err := os.WriteFile(hostnamesFile, []byte(newContent), 0644); err != nil {
		s.logger.Printf("write agate-hostnames: %v", err)
		return
	}
	if err := exec.Command("systemctl", "restart", "agate").Run(); err != nil {
		s.logger.Printf("restart agate: %v", err)
	}
}

func (s *Server) removeAgateHost(username string) {
	hostname := username + "." + s.cfg.Server.Domain
	hostnamesFile := "/etc/capsule-service/agate-hostnames"

	data, err := os.ReadFile(hostnamesFile)
	if err != nil {
		s.logger.Printf("read agate-hostnames: %v", err)
		return
	}
	current := strings.TrimSpace(string(data))
	current = strings.TrimPrefix(current, `AGATE_HOSTNAMES=`)
	current = strings.Trim(current, `"`)

	hosts := strings.Fields(current)
	filtered := hosts[:0]
	for _, h := range hosts {
		if h != hostname {
			filtered = append(filtered, h)
		}
	}
	newContent := fmt.Sprintf("AGATE_HOSTNAMES=\"%s\"\n", strings.Join(filtered, " "))
	if err := os.WriteFile(hostnamesFile, []byte(newContent), 0644); err != nil {
		s.logger.Printf("write agate-hostnames: %v", err)
		return
	}
	exec.Command("systemctl", "restart", "agate").Run()
}
