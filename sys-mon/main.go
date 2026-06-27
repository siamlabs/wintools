package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"sys-mon/ports"
)

type App struct{}

func NewApp() *App {
	return &App{}
}

func (a *App) Startup(ctx context.Context) {
	_ = ctx
	createTrayIcon()
}

func (a *App) Shutdown(ctx context.Context) {
	_ = ctx
	removeTrayIcon()
}

// ScanAndCompare scans ports and compares against baseline.
func (a *App) ScanAndCompare(baselineName string) (string, error) {
	b, err := ports.LoadBaseline(baselineName)
	if err != nil {
		return "", err
	}

	current, err := ports.GetPorts()
	if err != nil {
		return "", err
	}

	for i := range current {
		current[i] = ports.ResolveProcess(current[i])
	}

	anomalies := ports.CompareBaseline(b, current)

	result := struct {
		Anomalies []ports.Anomaly `json:"anomalies"`
		Ports     []ports.PortInfo `json:"ports"`
	}{
		Anomalies: anomalies,
		Ports:     current,
	}

	data, _ := json.Marshal(result)
	return string(data), nil
}

// WhitelistPort whitelists a port and updates the baseline.
func (a *App) WhitelistPort(portJSON string) (string, error) {
	var p ports.PortInfo
	if err := json.Unmarshal([]byte(portJSON), &p); err != nil {
		return "", err
	}

	b, err := ports.LoadBaseline("default")
	if err != nil {
		return "", err
	}

	for i := range b.Ports {
		if b.Ports[i].Port == p.Port && b.Ports[i].Protocol == p.Protocol && b.Ports[i].Family == p.Family && b.Ports[i].Address == p.Address {
			b.Ports[i].Whitelisted = true
			break
		}
	}

	if err := ports.SaveBaseline("default", b.Ports); err != nil {
		return "", err
	}

	return "ok", nil
}

// BlockPort creates a Windows Firewall deny rule.
func (a *App) BlockPort(portJSON string) (string, error) {
	var p ports.PortInfo
	if err := json.Unmarshal([]byte(portJSON), &p); err != nil {
		return "", err
	}

	ruleName := fmt.Sprintf("sys-mon-block-%s-%d", p.Protocol, p.Port)
	direction := "in"
	proto := strings.ToUpper(p.Protocol)
	localPort := fmt.Sprintf("%d", p.Port)

	cmdStr := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=%s protocol=%s localport=%s action=block`,
		ruleName, direction, proto, localPort)

	cmd := exec.Command("cmd", "/c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("firewall block failed: %s", string(output))
	}

	return "blocked", nil
}

// KillPort terminates the process listening on a port.
func (a *App) KillPort(portJSON string) (string, error) {
	var p ports.PortInfo
	if err := json.Unmarshal([]byte(portJSON), &p); err != nil {
		return "", err
	}

	if err := ports.KillProcess(p.PID); err != nil {
		return "", fmt.Errorf("kill failed: %w", err)
	}

	return "killed", nil
}

// ShowToast sends a Windows toast notification.
func (a *App) ShowToast(title, message string) (string, error) {
	return showToast(title, message)
}

// ShowCriticalToast sends a toast for critical threats.
func (a *App) ShowCriticalToast(portJSON string) (string, error) {
	var p ports.PortInfo
	if err := json.Unmarshal([]byte(portJSON), &p); err != nil {
		return "", err
	}

	title := "⚠ sys-mon — Critical Threat"
	msg := fmt.Sprintf("Unexpected port: %s:%d/%s (PID %d, %s)",
		p.Address, p.Port, p.Protocol, p.PID, p.Process)

	return showToast(title, msg)
}

// GetProcessInfo returns detailed process info.
func (a *App) GetProcessInfo(pid int) (string, error) {
	details := ports.GetProcessDetails(pid)
	data, _ := json.Marshal(details)
	return string(data), nil
}

// ListBaselines returns available baseline names.
func (a *App) ListBaselines() (string, error) {
	names, err := ports.ListBaselines()
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(names)
	return string(data), nil
}

// GetBaselineStatus returns the current baseline name and port count.
func (a *App) GetBaselineStatus() (string, error) {
	b, err := ports.LoadBaseline("default")
	if err != nil {
		return `{"name":"none","ports":0}`, nil
	}
	data, _ := json.Marshal(map[string]interface{}{
		"name":          b.Name,
		"ports":         len(b.Ports),
		"captured_at":   b.CapturedAt,
		"hostname":      b.Hostname,
		"admin":         b.Admin,
	})
	return string(data), nil
}

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:            "sys-mon",
		Width:            900,
		Height:           650,
		MinWidth:         700,
		MinHeight:        500,
		WindowStartState: options.Normal,
		BackgroundColour: &options.RGBA{R: 13, G: 17, B: 23, A: 255},
		Windows: &windows.Options{
			WebviewIsTransparent: true,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
		},
		OnStartup:  app.Startup,
		OnShutdown: app.Shutdown,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}

// ===== Windows Tray Icon =====

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	user32         = syscall.NewLazyDLL("user32.dll")
	shell32        = syscall.NewLazyDLL("shell32.dll")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
)

const (
	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002
	NIF_ICON   = 0x00000002
	NIF_TIP    = 0x00000004
	NIF_MESSAGE = 0x00000001
)

type NOTIFYICONDATA struct {
	cbSize       uint32
	HWnd         uintptr
	UID          uint32
	UFlags       uint32
	UCallbackMsg uint32
	HIcon        uintptr
	SzTip        [128]uint16
	DWState      uint32
	DWStateMask  uint32
	SzInfo       [256]uint16
	NVersion     uint32
	SzInfoTitle  [64]uint16
	DWInfoFlags  uint32
	GuidItem     [16]byte
	HBalloonIcon uintptr
}

var trayIcon NOTIFYICONDATA

func createTrayIcon() {
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	hInst, _, _ := getModuleHandle.Call(0)

	trayIcon = NOTIFYICONDATA{
		cbSize:       uint32(unsafe.Sizeof(NOTIFYICONDATA{})),
		HWnd:         0,
		UID:          1000,
		UFlags:       NIF_ICON | NIF_TIP,
		UCallbackMsg: 0x0400,
		HIcon:        hInst,
		SzTip:        [128]uint16{},
	}

	tip := "sys-mon"
	for i, c := range tip {
		trayIcon.SzTip[i] = uint16(c)
	}

	procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&trayIcon)))
}

func removeTrayIcon() {
	trayIcon.UFlags = 0
	procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&trayIcon)))
}

// ===== Windows Toast Notifications =====

func showToast(title, message string) (string, error) {
	// Use PowerShell to show a Windows toast notification
	psScript := fmt.Sprintf(`
		[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
		[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
		$toastXml = @"
		<toast>
			<visual>
				<binding template="ToastText02">
					<text id="1">%s</text>
					<text id="2">%s</text>
				</binding>
			</visual>
		</toast>
"@
		$toastDoc = New-Object Windows.Data.Xml.Dom.XmlDocument
		$toastDoc.LoadXml($toastXml)
		$toast = [Windows.UI.Notifications.ToastNotification]::new($toastDoc)
		[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("sys-mon").Show($toast)
	`, escapePS(title), escapePS(message))

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	err := cmd.Start()
	if err != nil {
		return "toast_failed", err
	}

	// Don't wait — toast should appear immediately
	go cmd.Wait()

	return "shown", nil
}

func escapePS(s string) string {
	return strings.ReplaceAll(s, "`", "``")
}
