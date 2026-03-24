package main

import (
	"log"
	"net/http"
	"os"

	"gemcities.com/capsule-service/api"
	"gemcities.com/capsule-service/config"
	"gemcities.com/capsule-service/db"
	"gemcities.com/capsule-service/email"
	"gemcities.com/capsule-service/files"
)

func main() {
	cfgPath := "/etc/capsule-service/config.toml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	database, err := db.Open(cfg.Server.DBPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()

	logFile, err := os.OpenFile(cfg.Server.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Fatalf("log: %v", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)

	mailer := email.New(cfg.Email)
	fm := files.New(
		cfg.Server.CapsuleRoot,
		cfg.Limits.MaxFileSizeBytes,
		cfg.Limits.MaxTotalStorageBytes,
		cfg.Limits.MaxFilesPerUser,
	)

	srv := api.NewServer(database, cfg, mailer, fm, logger)

	log.Printf("capsule-service listening on %s", cfg.Server.Listen)
	if err := http.ListenAndServe(cfg.Server.Listen, srv.Routes()); err != nil {
		log.Fatalf("server: %v", err)
	}
}
