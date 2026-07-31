package tun

// lx/040 (SPECS/TASKS/040-SINGTUN_ACCEPTLOOP_SELFHEAL): acceptLoop self-heal.
//
// Red/green против апстрима 2d9b8aed5fe2: там acceptLoop(listener) при любой
// ошибке Accept молча выходит навсегда — восстановления нет, порт не меняется,
// новый connect вечно бьётся в мёртвый сокет. Для red-прогона на чистом
// апстрим-чекауте достаточно адаптировать хелперы ниже (currentTCPPort →
// s.tcpPort, spawnAcceptLoop → go s.acceptLoop(ln)): тест упадёт по таймауту
// ожидания восстановления.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func newSelfHealTestSystem(t *testing.T) *System {
	t.Helper()
	s := &System{
		ctx:          context.Background(),
		logger:       logger.NOP(),
		inet4Address: netip.MustParseAddr("127.0.0.1"),
		udpTimeout:   time.Minute,
	}
	s.tcpNat = NewNat(s.ctx, s.udpTimeout)
	ln, err := s.listenTCP(false)
	if err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
	s.tcpListener = ln
	s.tcpPort.Store(uint32(ln.Addr().(*net.TCPAddr).Port))
	spawnAcceptLoop(s, ln)
	return s
}

func currentTCPPort(s *System) uint32 {
	return s.tcpPort.Load()
}

func spawnAcceptLoop(s *System, ln net.Listener) {
	go s.acceptLoop(ln, false)
}

func dialForwarder(t *testing.T, port uint32) error {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// Убийство listener'а мимо System.Close (эмуляция чужого close по
// переиспользованному fd-номеру) должно приводить к пересозданию listener'а
// и продолжению приёма TCP, а не к вечной смерти петли.
func TestSystemAcceptLoopSelfHeal(t *testing.T) {
	s := newSelfHealTestSystem(t)
	oldPort := currentTCPPort(s)

	if err := dialForwarder(t, oldPort); err != nil {
		t.Fatalf("healthy listener refused connect: %v", err)
	}

	// Убить listener из-под стека: closing НЕ выставлен.
	_ = s.tcpListener.Close()

	deadline := time.Now().Add(5 * time.Second)
	healed := false
	for time.Now().Before(deadline) {
		if s.acceptRecoveries.Load() > 0 {
			healed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !healed {
		t.Fatalf("acceptLoop did not recover within 5s (upstream behavior: silent permanent death)")
	}

	newPort := currentTCPPort(s)
	if newPort == oldPort {
		t.Fatalf("recovered port equals dead port %d — relisten did not publish a new port", oldPort)
	}
	if err := dialForwarder(t, newPort); err != nil {
		t.Fatalf("connect to recreated listener (port %d) failed: %v", newPort, err)
	}
	if got := s.acceptRecoveries.Load(); got != 1 {
		t.Fatalf("acceptRecoveries = %d, want 1", got)
	}

	s.closing.Store(true)
	_ = s.tcpListener.Close()
}

// Штатное закрытие (closing выставлен, как это делает System.Close) обязано
// оставаться тихим: без пересозданий и без роста счётчика.
func TestSystemAcceptLoopQuietOnClose(t *testing.T) {
	s := newSelfHealTestSystem(t)
	oldPort := currentTCPPort(s)

	s.closing.Store(true)
	_ = s.tcpListener.Close()

	time.Sleep(300 * time.Millisecond)
	if got := s.acceptRecoveries.Load(); got != 0 {
		t.Fatalf("deliberate close triggered %d recoveries, want 0", got)
	}
	if port := currentTCPPort(s); port != oldPort {
		t.Fatalf("deliberate close changed port %d → %d", oldPort, port)
	}
}
