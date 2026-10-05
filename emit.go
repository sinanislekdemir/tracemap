package main

import "errors"

// EventSink receives every event the backend emits. The UI installs one that
// marshals the payload onto the Qt GUI thread. A nil sink drops events.
type EventSink func(name string, payload any)

// FileFilter is a native file-dialog filter. Pattern is a semicolon-separated
// list of globs (for example "*.txt;*.lst").
type FileFilter struct {
	DisplayName string
	Pattern     string
}

// Dialogs abstracts the native dialogs the backend needs. The UI installs a Qt
// implementation; the built-in fallback cancels file dialogs and refuses
// confirmations.
type Dialogs interface {
	OpenFile(title string, filters []FileFilter) (string, error)
	SaveFile(title, defaultName string, filters []FileFilter) (string, error)
	Confirm(title, message string) bool
}

// noDialogs is the safe default before the UI installs a real implementation.
type noDialogs struct{}

func (noDialogs) OpenFile(string, []FileFilter) (string, error) { return "", nil }

func (noDialogs) SaveFile(string, string, []FileFilter) (string, error) {
	return "", errors.New("no dialog backend installed")
}

func (noDialogs) Confirm(string, string) bool { return false }

// SetEmitter installs the event sink. It must be called before any operation
// starts; the UI wires it to the Qt main thread.
func (a *App) SetEmitter(sink EventSink) {
	if sink == nil {
		a.emit = func(string, any) {}
		return
	}
	a.emit = sink
}

// SetDialogs installs the native dialog implementation.
func (a *App) SetDialogs(d Dialogs) {
	if d == nil {
		a.dialogs = noDialogs{}
		return
	}
	a.dialogs = d
}
