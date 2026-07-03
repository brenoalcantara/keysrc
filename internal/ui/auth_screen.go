package ui

import (
	"context"
	"errors"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/service"
	"keysrc/internal/storage"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type loginAttemptLimiter struct {
	failures int
}

func (l *loginAttemptLimiter) Delay() time.Duration {
	if l.failures <= 0 {
		return 0
	}

	delay := time.Duration(1<<min(l.failures-1, 4)) * time.Second
	if delay > 15*time.Second {
		return 15 * time.Second
	}

	return delay
}

func (l *loginAttemptLimiter) RecordFailure() {
	if l.failures < 16 {
		l.failures++
	}
}

func (l *loginAttemptLimiter) Reset() {
	l.failures = 0
}

func (r *Router) authScreen() fyne.CanvasObject {
	if r.deps.AuthService == nil {
		return r.errorScreen("Nao foi possivel iniciar a autenticacao.")
	}

	exists, err := r.deps.AuthService.HasVault(context.Background())
	if err != nil {
		return r.errorScreen("Nao foi possivel carregar o cofre.")
	}

	if exists {
		return r.loginScreen()
	}

	return r.createVaultScreen()
}

func (r *Router) createVaultScreen() fyne.CanvasObject {
	/* title := widget.NewLabelWithStyle("KeySrc", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subtitle := widget.NewLabelWithStyle("Criar cofre", fyne.TextAlignCenter, fyne.TextStyle{}) */

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Senha mestra")
	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("Confirmar senha mestra")

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	createButton := widget.NewButton("Criar cofre", nil)
	createButton.Importance = widget.HighImportance

	setBusy := func(busy bool) {
		if busy {
			passwordEntry.Disable()
			confirmEntry.Disable()
			createButton.Disable()
			progress.Show()
			return
		}

		passwordEntry.Enable()
		confirmEntry.Enable()
		createButton.Enable()
		progress.Hide()
	}

	clearEntries := func() {
		passwordEntry.SetText("")
		confirmEntry.SetText("")
	}

	createButton.OnTapped = func() {
		if passwordEntry.Text != confirmEntry.Text {
			clearEntries()
			status.SetText("As senhas não conferem.")
			return
		}

		password := []byte(passwordEntry.Text)
		clearEntries()
		status.SetText("Criando cofre...")
		setBusy(true)

		go func() {
			defer security.ZeroBytes(password)

			session, err := r.deps.AuthService.CreateVault(context.Background(), password)
			fyne.Do(func() {
				setBusy(false)

				if err != nil {
					if errors.Is(err, security.ErrWeakPassword) {
						status.SetText("A senha mestra não atende aos requisitos.")
						return
					}

					if errors.Is(err, storage.ErrAlreadyExists) {
						status.SetText("O cofre já foi criado.")
						r.setContent(r.loginScreen())
						return
					}

					status.SetText("Não foi possível criar o cofre.")
					return
				}

				r.showUnlocked(session)
			})
		}()
	}

	form := widget.NewForm(
		widget.NewFormItem("Senha mestra", passwordEntry),
		widget.NewFormItem("Confirmação", confirmEntry),
	)

	return centeredPanel(container.NewVBox(
		/* title,
		subtitle, */
		form,
		createButton,
		progress,
		status,
	))
}

func (r *Router) loginScreen() fyne.CanvasObject {
	/* title := widget.NewLabelWithStyle("KeySrc", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subtitle := widget.NewLabelWithStyle("Entrar", fyne.TextAlignCenter, fyne.TextStyle{}) */

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Senha mestra")

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	enterButton := widget.NewButton("Entrar", nil)
	enterButton.Importance = widget.HighImportance

	setBusy := func(busy bool) {
		if busy {
			passwordEntry.Disable()
			enterButton.Disable()
			progress.Show()
			return
		}

		passwordEntry.Enable()
		enterButton.Enable()
		progress.Hide()
	}

	enterButton.OnTapped = func() {
		password := []byte(passwordEntry.Text)
		passwordEntry.SetText("")

		status.SetText("Desbloqueando cofre...")
		setBusy(true)
		delay := r.loginLimiter.Delay()

		go func() {
			defer security.ZeroBytes(password)

			if delay > 0 {
				time.Sleep(delay)
			}

			session, err := r.deps.AuthService.UnlockVault(context.Background(), password)
			fyne.Do(func() {
				setBusy(false)

				if err != nil {
					r.loginLimiter.RecordFailure()
					status.SetText("Não foi possível desbloquear o cofre.")
					return
				}

				r.loginLimiter.Reset()
				r.showUnlocked(session)
			})
		}()
	}

	form := widget.NewForm(widget.NewFormItem("Senha mestra", passwordEntry))

	return centeredPanel(container.NewVBox(
		/* title,
		subtitle, */
		form,
		enterButton,
		progress,
		status,
	))
}

func (r *Router) showUnlocked(session *service.VaultSession) {
	if r.session != nil {
		r.session.Lock()
	}

	r.session = session
	r.setContent(r.credentialListScreen())
	r.markActivity()
}

func (r *Router) errorScreen(message string) fyne.CanvasObject {
	title := widget.NewLabelWithStyle("KeySrc", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	status := widget.NewLabelWithStyle(message, fyne.TextAlignCenter, fyne.TextStyle{})
	status.Wrapping = fyne.TextWrapWord

	return centeredPanel(container.NewVBox(title, status))
}

func centeredPanel(content fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&centeredPanelLayout{}, content)
}

const (
	centeredPanelMaxWidth          float32 = 560
	centeredPanelHorizontalPadding float32 = 32
)

type centeredPanelLayout struct{}

func (l *centeredPanelLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, child := range objects {
		if !child.Visible() {
			continue
		}

		minSize := child.MinSize()
		width := centeredPanelMaxWidth
		availableWidth := size.Width - centeredPanelHorizontalPadding*2
		if availableWidth < width {
			width = availableWidth
		}
		if width < minSize.Width {
			width = minSize.Width
		}
		if width > size.Width {
			width = size.Width
		}

		height := minSize.Height
		if height > size.Height {
			height = size.Height
		}

		child.Resize(fyne.NewSize(width, height))
		child.Move(fyne.NewPos((size.Width-width)/2, (size.Height-height)/2))
	}
}

func (l *centeredPanelLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	minSize := fyne.NewSize(0, 0)
	for _, child := range objects {
		if child.Visible() {
			minSize = minSize.Max(child.MinSize())
		}
	}

	return minSize
}
