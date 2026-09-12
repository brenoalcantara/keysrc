package ui

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/service"
	"keysrc/internal/storage"

	"fyne.io/fyne/v2"
	fynecontainer "fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestLoginScreenEntryUsesPanelWidth(t *testing.T) {
	test.NewTempApp(t)
	window := test.NewWindow(nil)
	t.Cleanup(window.Close)

	router := NewRouter(window, Dependencies{})
	content := router.loginScreen()
	window.SetContent(content)
	window.Resize(fyne.NewSize(960, 640))

	entries := collectEntries(content)
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}

	entryWidth := entries[0].Size().Width
	if entryWidth < 360 {
		t.Fatalf("login entry width = %.1f, want at least 360", entryWidth)
	}

	if entryWidth <= entries[0].MinSize().Width {
		t.Fatalf("login entry width = %.1f, min width = %.1f; entry stayed at MinSize", entryWidth, entries[0].MinSize().Width)
	}
}

func TestCreateVaultScreenEntriesUsePanelWidth(t *testing.T) {
	test.NewTempApp(t)
	window := test.NewWindow(nil)
	t.Cleanup(window.Close)

	router := NewRouter(window, Dependencies{})
	content := router.createVaultScreen()
	window.SetContent(content)
	window.Resize(fyne.NewSize(960, 640))

	entries := collectEntries(content)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}

	for i, entry := range entries {
		entryWidth := entry.Size().Width
		if entryWidth < 360 {
			t.Fatalf("entry %d width = %.1f, want at least 360", i, entryWidth)
		}
	}
}

func TestInitialScreenShowsCreateVaultForFirstAccessAndLoginForExistingVault(t *testing.T) {
	t.Run("first access", func(t *testing.T) {
		router, window, _, _ := newRouterForUITest(t)

		content := router.InitialScreen()
		window.SetContent(content)

		if findButton(content, "Criar cofre") == nil {
			t.Fatal("first access screen does not show create vault action")
		}

		if findButton(content, "Entrar") != nil {
			t.Fatal("first access screen shows login action")
		}

		entries := collectEntries(content)
		if len(entries) != 2 {
			t.Fatalf("first access entry count = %d, want 2", len(entries))
		}
	})

	t.Run("existing vault", func(t *testing.T) {
		router, window, authService, _ := newRouterForUITest(t)
		session, err := authService.CreateVault(context.Background(), []byte("Very-Strong-Passphrase-2026!"))
		if err != nil {
			t.Fatalf("create existing vault: %v", err)
		}
		session.Lock()

		content := router.InitialScreen()
		window.SetContent(content)

		if findButton(content, "Entrar") == nil {
			t.Fatal("existing vault screen does not show login action")
		}

		if findButton(content, "Criar cofre") != nil {
			t.Fatal("existing vault screen shows create vault action")
		}

		entries := collectEntries(content)
		if len(entries) != 1 {
			t.Fatalf("existing vault entry count = %d, want 1", len(entries))
		}
	})
}

func TestCreateVaultScreenTransitionsToCredentialList(t *testing.T) {
	router, window, _, _ := newRouterForUITest(t)
	content := router.InitialScreen()
	window.SetContent(content)

	entries := collectEntries(content)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}

	entries[0].SetText("Very-Strong-Passphrase-2026!")
	entries[1].SetText("Very-Strong-Passphrase-2026!")
	test.Tap(requireButton(t, content, "Criar cofre"))

	waitForWindowContent(t, window, func(content fyne.CanvasObject) bool {
		return findButton(content, "Nova credencial") != nil && findButton(content, "Bloquear") != nil
	})

	if router.session == nil || len(router.session.VaultKey) != security.KeySize {
		t.Fatal("router session was not unlocked after creating vault")
	}
}

func TestCredentialFormValidatesRequiredFields(t *testing.T) {
	router, window := newUnlockedRouterForUITest(t)

	test.Tap(requireButton(t, currentWindowContent(t, window), "Nova credencial"))
	content := currentWindowContent(t, window)

	if !hasLabel(content, "Nova credencial") {
		t.Fatal("credential form was not shown")
	}

	test.Tap(requireButton(t, content, "Salvar"))

	if !hasLabel(content, "Preencha titulo e senha.") {
		t.Fatal("credential form did not show required-field validation message")
	}

	if router.session == nil {
		t.Fatal("router session was unexpectedly locked")
	}
}

func TestChangeMasterPasswordRequiresConfirmation(t *testing.T) {
	_, window := newUnlockedRouterForUITest(t)

	test.Tap(requireButton(t, currentWindowContent(t, window), "Trocar senha"))
	content := currentWindowContent(t, window)

	if !hasLabel(content, "Trocar senha") {
		t.Fatal("change password screen was not shown")
	}

	entries := collectEntries(content)
	if len(entries) != 3 {
		t.Fatalf("change password entry count = %d, want 3", len(entries))
	}

	entries[0].SetText("Very-Strong-Passphrase-2026!")
	entries[1].SetText("Even-Stronger-Passphrase-2027!")
	entries[2].SetText("Different-Stronger-Passphrase-2027!")
	test.Tap(requireButton(t, content, "Salvar"))

	if !hasLabel(content, "As senhas nao conferem.") {
		t.Fatal("change password screen did not require confirmation match")
	}

	for i, entry := range entries {
		if entry.Text != "" {
			t.Fatalf("entry %d was not cleared after confirmation mismatch", i)
		}
	}
}

func TestLockButtonReturnsToLogin(t *testing.T) {
	router, window := newUnlockedRouterForUITest(t)

	test.Tap(requireButton(t, currentWindowContent(t, window), "Bloquear"))
	content := currentWindowContent(t, window)

	if router.session != nil {
		t.Fatal("router session still exists after lock")
	}

	if findButton(content, "Entrar") == nil {
		t.Fatal("lock did not return to login screen")
	}

	entries := collectEntries(content)
	if len(entries) != 1 {
		t.Fatalf("login entry count after lock = %d, want 1", len(entries))
	}
}

func collectEntries(object fyne.CanvasObject) []*widget.Entry {
	var entries []*widget.Entry

	walkCanvasObject(object, func(candidate fyne.CanvasObject) {
		if entry, ok := candidate.(*widget.Entry); ok {
			entries = append(entries, entry)
		}
	})

	return entries
}

func walkCanvasObject(object fyne.CanvasObject, visit func(fyne.CanvasObject)) {
	if object == nil {
		return
	}

	visit(object)

	if container, ok := object.(*fyne.Container); ok {
		for _, child := range container.Objects {
			walkCanvasObject(child, visit)
		}
	}

	if split, ok := object.(*fynecontainer.Split); ok {
		walkCanvasObject(split.Leading, visit)
		walkCanvasObject(split.Trailing, visit)
	}

	if form, ok := object.(*widget.Form); ok {
		for _, item := range form.Items {
			walkCanvasObject(item.Widget, visit)
		}
	}
}

func newRouterForUITest(t *testing.T) (*Router, fyne.Window, *service.AuthService, *service.CredentialService) {
	t.Helper()
	test.NewTempApp(t)
	window := test.NewWindow(nil)
	t.Cleanup(window.Close)

	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "keysrc.sqlite3")
	db, err := storage.Open(ctx, databasePath)
	if err != nil {
		t.Fatalf("open ui test database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close ui test database: %v", err)
		}
	})

	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate ui test database: %v", err)
	}

	authService := service.NewAuthServiceWithOptions(db, service.AuthOptions{
		KDFParams: uiTestKDFParams(),
	})
	credentialService := service.NewCredentialService(db)
	router := NewRouter(window, Dependencies{
		AuthService:       authService,
		CredentialService: credentialService,
		InactivityTimeout: -1,
	})
	t.Cleanup(func() {
		if router.session != nil {
			router.session.Lock()
		}
	})

	return router, window, authService, credentialService
}

func newUnlockedRouterForUITest(t *testing.T) (*Router, fyne.Window) {
	t.Helper()

	router, window, authService, _ := newRouterForUITest(t)
	session, err := authService.CreateVault(context.Background(), []byte("Very-Strong-Passphrase-2026!"))
	if err != nil {
		t.Fatalf("create ui test vault: %v", err)
	}

	router.showUnlocked(session)
	return router, window
}

func uiTestKDFParams() security.KDFParams {
	return security.KDFParams{
		MemoryKiB:   security.MinimumKDFMemoryKiB,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  security.MinimumKDFSaltLength,
		KeyLength:   security.KeySize,
	}
}

func currentWindowContent(t *testing.T, window fyne.Window) fyne.CanvasObject {
	t.Helper()

	content := window.Canvas().Content()
	if content == nil {
		t.Fatal("window content is nil")
	}

	return content
}

func waitForWindowContent(t *testing.T, window fyne.Window, condition func(fyne.CanvasObject) bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var done bool
		fyne.DoAndWait(func() {
			content := window.Canvas().Content()
			done = content != nil && condition(content)
		})
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("timed out waiting for expected window content")
}

func requireButton(t *testing.T, object fyne.CanvasObject, text string) *widget.Button {
	t.Helper()

	button := findButton(object, text)
	if button == nil {
		t.Fatalf("button %q not found", text)
	}

	return button
}

func findButton(object fyne.CanvasObject, text string) *widget.Button {
	var found *widget.Button
	walkCanvasObject(object, func(candidate fyne.CanvasObject) {
		if found != nil {
			return
		}

		if button, ok := candidate.(*widget.Button); ok && button.Text == text {
			found = button
		}
	})

	return found
}

func hasLabel(object fyne.CanvasObject, text string) bool {
	var found bool
	walkCanvasObject(object, func(candidate fyne.CanvasObject) {
		if label, ok := candidate.(*widget.Label); ok && label.Text == text {
			found = true
		}
	})

	return found
}
