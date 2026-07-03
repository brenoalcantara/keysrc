package app

import (
	"context"
	"fmt"

	"keysrc/internal/service"
	"keysrc/internal/storage"
	"keysrc/internal/ui"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
)

func Run() error {
	ctx := context.Background()
	cfg := DefaultConfig()

	dataDir, err := EnsureDataDir()
	if err != nil {
		return err
	}

	databasePath := DatabasePath(dataDir)
	db, err := storage.Open(ctx, databasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := storage.Migrate(ctx, db); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	if err := storage.SecureDatabaseFiles(databasePath); err != nil {
		return err
	}

	application := fyneapp.NewWithID(cfg.ID)
	window := application.NewWindow(cfg.Name)
	authService := service.NewAuthService(db)
	credentialService := service.NewCredentialService(db)
	router := ui.NewRouter(window, ui.Dependencies{
		AuthService:       authService,
		CredentialService: credentialService,
		DataDir:           dataDir,
		DatabasePath:      databasePath,
		SchemaVersion:     storage.CurrentSchemaVersion,
	})

	window.SetContent(router.InitialScreen())
	window.Resize(fyne.NewSize(cfg.WindowWidth, cfg.WindowHeight))
	window.CenterOnScreen()
	window.ShowAndRun()

	return nil
}
