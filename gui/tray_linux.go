package main

// From encedo-wg-hsm's gui/tray_linux.go (MIT, same author). A Linux desktop
// does not necessarily have a tray: Fyne registers the menu over D-Bus and a
// failure only reaches its log. Stock GNOME owns the watcher name without
// implementing it, so the question asked is whether a *host* is registered.
// Without one the window stays visible instead of hiding into nowhere.

import "github.com/godbus/dbus/v5"

const (
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = "/StatusNotifierWatcher"
	hostRegProp  = "org.kde.StatusNotifierWatcher.IsStatusNotifierHostRegistered"
	nameHasOwner = "org.freedesktop.DBus.NameHasOwner"
)

func trayAvailable() bool {
	conn, err := dbus.SessionBus()
	if err != nil {
		return false
	}
	var owned bool
	if err := conn.BusObject().Call(nameHasOwner, 0, watcherName).Store(&owned); err != nil || !owned {
		return false
	}
	v, err := conn.Object(watcherName, watcherPath).GetProperty(hostRegProp)
	if err != nil {
		return false
	}
	registered, ok := v.Value().(bool)
	return ok && registered
}
