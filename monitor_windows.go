package tun

import (
	"runtime"
	"slices"
	"sync"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const registryNotifyFilter = windows.REG_NOTIFY_CHANGE_NAME | windows.REG_NOTIFY_CHANGE_LAST_SET | windows.REG_NOTIFY_THREAD_AGNOSTIC

var dnsRegistryPaths = []string{
	`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
	`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
}

type networkUpdateMonitor struct {
	routeListener     *winipcfg.RouteChangeCallback
	interfaceListener *winipcfg.InterfaceChangeCallback
	dnsWatcher        *registryWatcher

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	return &networkUpdateMonitor{
		logger: logger,
	}, nil
}

func (m *networkUpdateMonitor) Start() error {
	routeListener, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		m.emit()
	})
	if err != nil {
		return err
	}
	interfaceListener, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		m.emit()
	})
	if err != nil {
		routeListener.Unregister()
		return err
	}
	dnsWatcher, err := newRegistryWatcher(dnsRegistryPaths, m.emit, m.logger)
	if err != nil {
		routeListener.Unregister()
		interfaceListener.Unregister()
		return err
	}
	m.routeListener = routeListener
	m.interfaceListener = interfaceListener
	m.dnsWatcher = dnsWatcher
	return nil
}

func (m *networkUpdateMonitor) Close() error {
	if m.routeListener != nil {
		m.routeListener.Unregister()
		m.routeListener = nil
	}
	if m.interfaceListener != nil {
		m.interfaceListener.Unregister()
		m.interfaceListener = nil
	}
	if m.dnsWatcher != nil {
		m.dnsWatcher.Close()
		m.dnsWatcher = nil
	}
	return nil
}

type registryWatcher struct {
	paths  []string
	keys   []registry.Key
	events []windows.Handle
	filter uint32
	done   chan struct{}
}

func newRegistryWatcher(paths []string, callback func(), logger logger.Logger) (*registryWatcher, error) {
	closeEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, E.Cause(err, "create event")
	}
	watcher := &registryWatcher{
		paths:  paths,
		events: []windows.Handle{closeEvent},
		filter: registryNotifyFilter,
		done:   make(chan struct{}),
	}
	for _, path := range paths {
		var key registry.Key
		key, err = registry.OpenKey(registry.LOCAL_MACHINE, path, registry.NOTIFY)
		if err != nil {
			watcher.release()
			return nil, E.Cause(err, "open registry key ", path)
		}
		watcher.keys = append(watcher.keys, key)
		var event windows.Handle
		event, err = windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			watcher.release()
			return nil, E.Cause(err, "create event")
		}
		watcher.events = append(watcher.events, event)
	}
	// lx: SPEC 130 — notifications are armed on the loop's locked thread (see notify)
	armed := make(chan error, 1)
	go watcher.loop(callback, logger, armed)
	err = <-armed
	if err != nil {
		<-watcher.done
		watcher.release()
		return nil, err
	}
	return watcher, nil
}

// lx: SPEC 130 — Windows 7 rejects REG_NOTIFY_THREAD_AGNOSTIC (Windows 8+) with
// ERROR_INVALID_PARAMETER. Without the flag a notification is cancelled when the
// registering thread exits, so all registrations happen on the loop goroutine,
// which stays locked to its OS thread for the watcher's lifetime.
func (w *registryWatcher) notify(index int) error {
	err := windows.RegNotifyChangeKeyValue(windows.Handle(w.keys[index]), true, w.filter, w.events[index+1], true)
	if err == windows.ERROR_INVALID_PARAMETER && w.filter&windows.REG_NOTIFY_THREAD_AGNOSTIC != 0 {
		w.filter &^= windows.REG_NOTIFY_THREAD_AGNOSTIC
		err = windows.RegNotifyChangeKeyValue(windows.Handle(w.keys[index]), true, w.filter, w.events[index+1], true)
	}
	return err
}

func (w *registryWatcher) loop(callback func(), logger logger.Logger, armed chan<- error) {
	defer close(w.done)
	// lx: SPEC 130 — never unlocked: the thread exits together with the goroutine
	runtime.LockOSThread()
	for index, path := range w.paths {
		err := w.notify(index)
		if err != nil {
			armed <- E.Cause(err, "watch registry key ", path)
			return
		}
	}
	armed <- nil
	for {
		event, err := windows.WaitForMultipleObjects(w.events, false, windows.INFINITE)
		if err != nil {
			logger.Error("wait registry change: ", err)
			return
		}
		index := int(event - windows.WAIT_OBJECT_0)
		if index == 0 {
			return
		}
		err = w.notify(index - 1)
		if err != nil {
			logger.Error("watch registry key: ", err)
			return
		}
		callback()
	}
}

func (w *registryWatcher) Close() {
	windows.SetEvent(w.events[0])
	<-w.done
	w.release()
}

func (w *registryWatcher) release() {
	for _, key := range w.keys {
		key.Close()
	}
	for _, event := range w.events {
		windows.CloseHandle(event)
	}
}

func (m *defaultInterfaceMonitor) checkUpdate() error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}

	lowestMetric := ^uint32(0)
	alias := ""
	var (
		index int
		luid  winipcfg.LUID
	)

	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}

		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		if ifrow.Type == winipcfg.IfTypePropVirtual || ifrow.Type == winipcfg.IfTypeSoftwareLoopback {
			continue
		}

		iface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}

		if !iface.Connected {
			continue
		}

		metric := row.Metric + iface.Metric
		if metric < lowestMetric {
			lowestMetric = metric
			alias = ifrow.Alias()
			index = int(ifrow.InterfaceIndex)
			luid = row.InterfaceLUID
		}
	}

	if alias == "" {
		return ErrNoRoute
	}

	newInterface, err := m.interfaceFinder.ByIndex(index)
	if err != nil {
		return E.Cause(err, "find updated interface: ", alias)
	}
	dnsServers, err := luid.DNS()
	if err != nil {
		return E.Cause(err, "read DNS servers: ", alias)
	}
	oldInterface := m.defaultInterface.Swap(newInterface)
	oldDNSServers := m.defaultDNSServers
	m.defaultDNSServers = dnsServers
	if !defaultInterfaceChanged(oldInterface, newInterface) && slices.Equal(oldDNSServers, dnsServers) {
		return nil
	}
	m.emit(newInterface, 0)
	return nil
}
