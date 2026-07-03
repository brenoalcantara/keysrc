package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"keysrc/internal/security"
	"keysrc/internal/service"
	"keysrc/internal/storage"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func (r *Router) credentialListScreen() fyne.CanvasObject {
	if r.session == nil || r.deps.CredentialService == nil {
		return r.loginScreen()
	}
	r.markActivity()

	var credentials []service.Credential
	var filtered []service.Credential
	var selected *service.Credential

	title := widget.NewLabelWithStyle("KeySrc", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Buscar")

	detailTitle := widget.NewLabelWithStyle("Selecione uma credencial", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	detailUsername := widget.NewLabel("")
	detailURL := widget.NewLabel("")
	detailTags := widget.NewLabel("")
	detailNotes := widget.NewLabel("")
	detailPassword := widget.NewLabel("Senha oculta")
	for _, label := range []*widget.Label{detailUsername, detailURL, detailTags, detailNotes, detailPassword} {
		label.Wrapping = fyne.TextWrapWord
	}

	copyUsernameButton := widget.NewButton("Copiar usuario", nil)
	copyPasswordButton := widget.NewButton("Copiar senha", nil)
	editButton := widget.NewButton("Editar", nil)
	deleteButton := widget.NewButton("Excluir", nil)
	refreshButton := widget.NewButton("Atualizar", nil)
	changePasswordButton := widget.NewButton("Trocar senha", func() {
		r.markActivity()
		r.setContent(r.changeMasterPasswordScreen())
	})
	newButton := widget.NewButton("Nova credencial", nil)
	newButton.Importance = widget.HighImportance
	lockButton := widget.NewButton("Bloquear", func() {
		r.lockVault()
	})

	actionButtons := []*widget.Button{copyUsernameButton, copyPasswordButton, editButton, deleteButton}
	setActionButtonsEnabled := func(enabled bool) {
		for _, button := range actionButtons {
			if enabled {
				button.Enable()
			} else {
				button.Disable()
			}
		}
	}
	setActionButtonsEnabled(false)

	list := widget.NewList(
		func() int {
			return len(filtered)
		},
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				widget.NewLabel(""),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(filtered) {
				return
			}

			credential := filtered[id]
			box := item.(*fyne.Container)
			titleLabel := box.Objects[0].(*widget.Label)
			metaLabel := box.Objects[1].(*widget.Label)

			titleLabel.SetText(credential.Title)
			metaLabel.SetText(compactCredentialMeta(credential))
		},
	)

	clearSelection := func() {
		selected = nil
		detailTitle.SetText("Selecione uma credencial")
		detailUsername.SetText("")
		detailURL.SetText("")
		detailTags.SetText("")
		detailNotes.SetText("")
		detailPassword.SetText("Senha oculta")
		setActionButtonsEnabled(false)
		list.UnselectAll()
	}

	showSelected := func(credential service.Credential) {
		selectedCredential := credential
		selected = &selectedCredential
		detailTitle.SetText(credential.Title)
		detailUsername.SetText("Usuario: " + fallbackText(credential.Username))
		detailURL.SetText("URL: " + fallbackText(credential.URL))
		detailTags.SetText("Tags: " + fallbackText(strings.Join(credential.Tags, ", ")))
		detailNotes.SetText("Notas: " + fallbackText(credential.Notes))
		detailPassword.SetText("Senha oculta")
		setActionButtonsEnabled(true)
	}

	applyFilter := func(query string) {
		query = strings.ToLower(strings.TrimSpace(query))
		filtered = filtered[:0]

		for _, credential := range credentials {
			if query == "" || credentialMatches(credential, query) {
				filtered = append(filtered, credential)
			}
		}

		clearSelection()
		list.Refresh()
		if len(filtered) == 0 {
			status.SetText("Nenhuma credencial encontrada.")
			return
		}

		status.SetText(fmt.Sprintf("%d credencial(is).", len(filtered)))
	}

	loadCredentials := func() {
		loaded, err := r.deps.CredentialService.List(context.Background(), r.session)
		if err != nil {
			status.SetText("Nao foi possivel carregar as credenciais.")
			return
		}

		credentials = loaded
		filtered = make([]service.Credential, 0, len(credentials))
		applyFilter(searchEntry.Text)
	}

	list.OnSelected = func(id widget.ListItemID) {
		r.markActivity()
		if id < 0 || id >= len(filtered) {
			clearSelection()
			return
		}

		showSelected(filtered[id])
	}

	searchEntry.OnChanged = func(query string) {
		r.markActivity()
		applyFilter(query)
	}

	newButton.OnTapped = func() {
		r.markActivity()
		r.setContent(r.credentialFormScreen(nil))
	}

	refreshButton.OnTapped = func() {
		r.markActivity()
		loadCredentials()
	}

	editButton.OnTapped = func() {
		r.markActivity()
		if selected == nil {
			return
		}

		credential := *selected
		r.setContent(r.credentialFormScreen(&credential))
	}

	deleteButton.OnTapped = func() {
		r.markActivity()
		if selected == nil {
			return
		}

		credential := *selected
		dialog.ShowConfirm("Excluir credencial", "Excluir esta credencial?", func(confirm bool) {
			if !confirm {
				return
			}

			if err := r.deps.CredentialService.Delete(context.Background(), r.session, credential.ID); err != nil {
				status.SetText("Nao foi possivel excluir a credencial.")
				return
			}

			status.SetText("Credencial excluida.")
			loadCredentials()
		}, r.window)
	}

	copyUsernameButton.OnTapped = func() {
		r.markActivity()
		if selected == nil {
			return
		}

		r.copyToClipboard(selected.Username)
		status.SetText("Usuario copiado.")
		r.clearClipboardLater(selected.Username, 45*time.Second)
	}

	copyPasswordButton.OnTapped = func() {
		r.markActivity()
		if selected == nil {
			return
		}

		copied := selected.Password
		r.copyToClipboard(copied)
		status.SetText("Senha copiada.")
		r.clearClipboardLater(copied, 45*time.Second)
	}

	topBar := container.NewBorder(nil, nil, title, container.NewHBox(newButton, refreshButton, changePasswordButton, lockButton), searchEntry)
	details := container.NewVBox(
		detailTitle,
		detailUsername,
		detailURL,
		detailTags,
		detailNotes,
		detailPassword,
		container.NewGridWithColumns(2, copyUsernameButton, copyPasswordButton),
		container.NewGridWithColumns(2, editButton, deleteButton),
		status,
	)

	content := container.NewHSplit(list, container.NewPadded(details))
	content.Offset = 0.48
	loadCredentials()

	return container.NewBorder(topBar, nil, nil, nil, content)
}

func (r *Router) changeMasterPasswordScreen() fyne.CanvasObject {
	if r.session == nil || r.deps.AuthService == nil {
		return r.loginScreen()
	}
	r.markActivity()

	title := widget.NewLabelWithStyle("Trocar senha", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	currentPasswordEntry := widget.NewPasswordEntry()
	currentPasswordEntry.SetPlaceHolder("Senha mestra atual")
	newPasswordEntry := widget.NewPasswordEntry()
	newPasswordEntry.SetPlaceHolder("Nova senha mestra")
	confirmPasswordEntry := widget.NewPasswordEntry()
	confirmPasswordEntry.SetPlaceHolder("Confirmar nova senha mestra")

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	saveButton := widget.NewButton("Salvar", nil)
	saveButton.Importance = widget.HighImportance
	cancelButton := widget.NewButton("Cancelar", func() {
		r.markActivity()
		clearCredentialForm(currentPasswordEntry, newPasswordEntry, confirmPasswordEntry)
		r.setContent(r.credentialListScreen())
	})

	setBusy := func(busy bool) {
		if busy {
			currentPasswordEntry.Disable()
			newPasswordEntry.Disable()
			confirmPasswordEntry.Disable()
			saveButton.Disable()
			cancelButton.Disable()
			progress.Show()
			return
		}

		currentPasswordEntry.Enable()
		newPasswordEntry.Enable()
		confirmPasswordEntry.Enable()
		saveButton.Enable()
		cancelButton.Enable()
		progress.Hide()
	}

	clearEntries := func() {
		clearCredentialForm(currentPasswordEntry, newPasswordEntry, confirmPasswordEntry)
	}

	saveButton.OnTapped = func() {
		r.markActivity()
		if newPasswordEntry.Text != confirmPasswordEntry.Text {
			clearEntries()
			status.SetText("As senhas nao conferem.")
			return
		}

		currentPassword := []byte(currentPasswordEntry.Text)
		newPassword := []byte(newPasswordEntry.Text)
		clearEntries()
		status.SetText("Atualizando senha mestra...")
		setBusy(true)

		go func() {
			defer security.ZeroBytes(currentPassword)
			defer security.ZeroBytes(newPassword)

			session, err := r.deps.AuthService.ChangeMasterPassword(context.Background(), currentPassword, newPassword)
			fyne.Do(func() {
				setBusy(false)

				if err != nil {
					if errors.Is(err, security.ErrWeakPassword) {
						status.SetText("A nova senha nao atende aos requisitos.")
						return
					}

					status.SetText("Nao foi possivel trocar a senha mestra.")
					return
				}

				r.showUnlocked(session)
			})
		}()
	}

	form := widget.NewForm(
		widget.NewFormItem("Senha atual", currentPasswordEntry),
		widget.NewFormItem("Nova senha", newPasswordEntry),
		widget.NewFormItem("Confirmacao", confirmPasswordEntry),
	)

	return centeredPanel(container.NewVBox(
		title,
		form,
		container.NewGridWithColumns(2, saveButton, cancelButton),
		progress,
		status,
	))
}

func (r *Router) credentialFormScreen(existing *service.Credential) fyne.CanvasObject {
	if r.session == nil || r.deps.CredentialService == nil {
		return r.loginScreen()
	}
	r.markActivity()

	isEditing := existing != nil
	title := widget.NewLabelWithStyle("Nova credencial", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	if isEditing {
		title.SetText("Editar credencial")
	}

	titleEntry := widget.NewEntry()
	titleEntry.SetPlaceHolder("Titulo")
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Usuario")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Senha")
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("URL")
	notesEntry := widget.NewMultiLineEntry()
	notesEntry.SetPlaceHolder("Notas")
	tagsEntry := widget.NewEntry()
	tagsEntry.SetPlaceHolder("Tags separadas por virgula")
	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord

	if isEditing {
		titleEntry.SetText(existing.Title)
		usernameEntry.SetText(existing.Username)
		passwordEntry.SetText(existing.Password)
		urlEntry.SetText(existing.URL)
		notesEntry.SetText(existing.Notes)
		tagsEntry.SetText(strings.Join(existing.Tags, ", "))
	}

	saveButton := widget.NewButton("Salvar", nil)
	saveButton.Importance = widget.HighImportance
	cancelButton := widget.NewButton("Cancelar", func() {
		r.markActivity()
		clearCredentialForm(titleEntry, usernameEntry, passwordEntry, urlEntry, notesEntry, tagsEntry)
		r.setContent(r.credentialListScreen())
	})
	generateButton := widget.NewButton("Gerar senha", func() {
		r.markActivity()
		password, err := r.deps.CredentialService.GeneratePassword(security.DefaultPasswordGeneratorOptions())
		if err != nil {
			status.SetText("Nao foi possivel gerar a senha.")
			return
		}

		passwordEntry.SetText(password)
		status.SetText("Senha gerada.")
	})

	saveButton.OnTapped = func() {
		r.markActivity()
		input := service.CredentialInput{
			Title:    titleEntry.Text,
			Username: usernameEntry.Text,
			Password: passwordEntry.Text,
			URL:      urlEntry.Text,
			Notes:    notesEntry.Text,
			Tags:     parseTags(tagsEntry.Text),
		}

		var err error
		if isEditing {
			_, err = r.deps.CredentialService.Update(context.Background(), r.session, existing.ID, input)
		} else {
			_, err = r.deps.CredentialService.Create(context.Background(), r.session, input)
		}

		if err != nil {
			if errors.Is(err, storage.ErrInvalidRecord) {
				status.SetText("Preencha titulo e senha.")
				return
			}

			status.SetText("Nao foi possivel salvar a credencial.")
			return
		}

		clearCredentialForm(titleEntry, usernameEntry, passwordEntry, urlEntry, notesEntry, tagsEntry)
		r.setContent(r.credentialListScreen())
	}

	form := widget.NewForm(
		widget.NewFormItem("Titulo", titleEntry),
		widget.NewFormItem("Usuario", usernameEntry),
		widget.NewFormItem("Senha", passwordEntry),
		widget.NewFormItem("URL", urlEntry),
		widget.NewFormItem("Notas", notesEntry),
		widget.NewFormItem("Tags", tagsEntry),
	)

	return centeredPanel(container.NewVBox(
		title,
		form,
		container.NewGridWithColumns(3, saveButton, generateButton, cancelButton),
		status,
	))
}

func (r *Router) lockVault() {
	r.stopInactivityTimer()
	r.clearTrackedClipboard()
	if r.session != nil {
		r.session.Lock()
		r.session = nil
	}

	r.setContent(r.loginScreen())
}

func compactCredentialMeta(credential service.Credential) string {
	switch {
	case credential.Username != "" && credential.URL != "":
		return credential.Username + " - " + credential.URL
	case credential.Username != "":
		return credential.Username
	case credential.URL != "":
		return credential.URL
	default:
		return "Sem usuario ou URL"
	}
}

func credentialMatches(credential service.Credential, query string) bool {
	values := []string{
		credential.Title,
		credential.Username,
		credential.URL,
		credential.Notes,
		strings.Join(credential.Tags, " "),
	}

	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}

	return false
}

func fallbackText(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}

	return value
}

func parseTags(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	return strings.Split(value, ",")
}

func clearCredentialForm(entries ...*widget.Entry) {
	for _, entry := range entries {
		entry.SetText("")
	}
}

func (r *Router) copyToClipboard(value string) {
	fyne.CurrentApp().Clipboard().SetContent(value)
	r.trackedClipboardContent = value
}

func (r *Router) clearClipboardLater(value string, delay time.Duration) {
	go func() {
		time.Sleep(delay)
		fyne.Do(func() {
			clipboard := fyne.CurrentApp().Clipboard()
			if clipboard.Content() == value {
				clipboard.SetContent("")
				if r.trackedClipboardContent == value {
					r.trackedClipboardContent = ""
				}
			}
		})
	}()
}

func (r *Router) clearTrackedClipboard() {
	if r.trackedClipboardContent == "" {
		return
	}

	clipboard := fyne.CurrentApp().Clipboard()
	if clipboard.Content() == r.trackedClipboardContent {
		clipboard.SetContent("")
	}
	r.trackedClipboardContent = ""
}
