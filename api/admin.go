package api

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"gemcities.com/capsule-service/auth"
	"gemcities.com/capsule-service/email"
)

func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" || token != s.cfg.Auth.AdminSecret {
			http.Error(w, `{"error":"UNAUTHORIZED"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/users",                        s.adminMiddleware(s.handleAdminListUsers))
	mux.HandleFunc("DELETE /api/admin/users/{username}",          s.adminMiddleware(s.handleAdminDeleteUser))
	mux.HandleFunc("POST /api/admin/users/{username}/verify",     s.adminMiddleware(s.handleAdminForceVerify))
	mux.HandleFunc("POST /api/admin/users/{username}/resend",     s.adminMiddleware(s.handleAdminResendVerification))
	mux.HandleFunc("POST /api/admin/users/{username}/email",      s.adminMiddleware(s.handleAdminChangeEmail))
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(
		`SELECT id, username, email, email_verified, storage_bytes, created_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR")
		return
	}
	defer rows.Close()

	type userRow struct {
		ID            int64  `json:"id"`
		Username      string `json:"username"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		StorageBytes  int64  `json:"storage_bytes"`
		CreatedAt     string `json:"created_at"`
	}

	var users []userRow
	for rows.Next() {
		var u userRow
		var verified int
		var createdAt int64
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &verified, &u.StorageBytes, &createdAt); err != nil {
			continue
		}
		u.EmailVerified = verified == 1
		u.CreatedAt = time.Unix(createdAt, 0).UTC().Format("2006-01-02 15:04")
		users = append(users, u)
	}
	if users == nil {
		users = []userRow{}
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}

	if err := s.files.DeleteAll(username); err != nil {
		s.logger.Printf("admin delete files for %s: %v", username, err)
	}
	s.db.Exec(`DELETE FROM users WHERE username=?`, username)
	go s.removeAgateHost(username)
	go func() {
		certDir := fmt.Sprintf("/etc/agate/certs/%s.%s", username, s.cfg.Server.Domain)
		os.RemoveAll(certDir)
	}()

	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleAdminForceVerify(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	res, err := s.db.Exec(
		`UPDATE users SET email_verified=1 WHERE username=? AND email_verified=0`, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, http.StatusNotFound, "NOT_FOUND")
		return
	}

	// Provision capsule if not already done
	if err := s.files.InitCapsule(username); err != nil {
		s.logger.Printf("admin init capsule for %s: %v", username, err)
	} else {
		go s.addAgateHost(username)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleAdminResendVerification(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")

	var userID int64
	var emailAddr string
	var verified int
	err := s.db.QueryRow(
		`SELECT id, email, email_verified FROM users WHERE username=?`, username).
		Scan(&userID, &emailAddr, &verified)
	if err != nil {
		writeErr(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if verified == 1 {
		writeErr(w, http.StatusBadRequest, "ALREADY_VERIFIED")
		return
	}

	plain, hashed, err := auth.GenerateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR")
		return
	}
	expiry := time.Now().Add(24 * time.Hour)
	if err := auth.StoreVerificationToken(s.db, userID, hashed, expiry); err != nil {
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR")
		return
	}

	mailer := email.New(s.cfg.Email)
	go func() {
		if err := mailer.SendVerification(emailAddr, username, plain, s.cfg.Server.Domain); err != nil {
			s.logger.Printf("admin resend verification for %s: %v", username, err)
		}
	}()
	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}

func (s *Server) handleAdminChangeEmail(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !emailRe.MatchString(req.Email) {
		writeErr(w, http.StatusBadRequest, "INVALID_EMAIL")
		return
	}

	res, err := s.db.Exec(
		`UPDATE users SET email=?, email_verified=0 WHERE username=?`, req.Email, username)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "EMAIL_TAKEN")
			return
		}
		writeErr(w, http.StatusInternalServerError, "SERVER_ERROR")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, http.StatusNotFound, "NOT_FOUND")
		return
	}

	// Resend verification to new address
	var userID int64
	s.db.QueryRow(`SELECT id FROM users WHERE username=?`, username).Scan(&userID)
	plain, hashed, _ := auth.GenerateToken()
	expiry := time.Now().Add(24 * time.Hour)
	auth.StoreVerificationToken(s.db, userID, hashed, expiry)

	mailer := email.New(s.cfg.Email)
	go func() {
		if err := mailer.SendVerification(req.Email, username, plain, s.cfg.Server.Domain); err != nil {
			s.logger.Printf("admin change email resend for %s: %v", username, err)
		}
	}()

	// Also remove old Agate hostname since capsule may need restart
	exec.Command("systemctl", "restart", "agate").Run()

	writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
}
