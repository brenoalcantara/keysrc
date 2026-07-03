package ui

import (
	"testing"

	"fyne.io/fyne/v2"
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

	if form, ok := object.(*widget.Form); ok {
		for _, item := range form.Items {
			walkCanvasObject(item.Widget, visit)
		}
	}
}
