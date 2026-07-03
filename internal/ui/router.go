package ui

import (
	"sync"
	"time"

	"keysrc/internal/service"

	"fyne.io/fyne/v2"
)

const defaultInactivityTimeout = 5 * time.Minute

type Dependencies struct {
	AuthService       *service.AuthService
	CredentialService *service.CredentialService
	InactivityTimeout time.Duration
	DataDir           string
	DatabasePath      string
	SchemaVersion     int
}

type Router struct {
	window                  fyne.Window
	deps                    Dependencies
	loginLimiter            loginAttemptLimiter
	session                 *service.VaultSession
	inactivityMu            sync.Mutex
	inactivityTimer         *time.Timer
	trackedClipboardContent string
}

func NewRouter(window fyne.Window, deps Dependencies) *Router {
	if deps.InactivityTimeout == 0 {
		deps.InactivityTimeout = defaultInactivityTimeout
	}

	return &Router{
		window: window,
		deps:   deps,
	}
}

func (r *Router) InitialScreen() fyne.CanvasObject {
	return r.authScreen()
}

func (r *Router) setContent(content fyne.CanvasObject) {
	r.window.SetContent(content)
}

func (r *Router) markActivity() {
	if r.session == nil || r.deps.InactivityTimeout <= 0 {
		return
	}

	r.inactivityMu.Lock()
	defer r.inactivityMu.Unlock()

	if r.inactivityTimer == nil {
		r.inactivityTimer = time.AfterFunc(r.deps.InactivityTimeout, func() {
			fyne.Do(func() {
				r.lockVault()
			})
		})
		return
	}

	r.inactivityTimer.Reset(r.deps.InactivityTimeout)
}

func (r *Router) stopInactivityTimer() {
	r.inactivityMu.Lock()
	defer r.inactivityMu.Unlock()

	if r.inactivityTimer != nil {
		r.inactivityTimer.Stop()
		r.inactivityTimer = nil
	}
}
