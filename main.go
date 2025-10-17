package main

import (
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "os"
    "time"

    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "github.com/keys-pub/go-libfido2"
)

var (
    titleStyle = lipgloss.NewStyle().
        Bold(true).
        Foreground(lipgloss.Color("86")).
        MarginBottom(1)

    errorStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("196")).
        Bold(true)

    successStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("46")).
        Bold(true)

    warningStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("226")).
        Bold(true)

    normalStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("252"))
)

type state int

const (
    stateInit state = iota
    stateDeviceCheck
    statePINEntry
    stateRegistering
    stateWaitingForTouch
    stateTouchDetected
    stateError
)

type model struct {
    state         state
    devicePath    string
    logs          []string
    err           error
    touchStart    time.Time
    touchDuration time.Duration
    registered    bool
    testCount     int
    pin           string
    pinInput      string
}

type deviceFoundMsg struct {
    path string
}

type registrationSuccessMsg struct{}

type touchSuccessMsg struct {
    duration time.Duration
}

type errorMsg struct {
    err error
}

func initialModel() model {
    return model{
        state: stateInit,
        logs:  []string{},
    }
}

func (m model) Init() tea.Cmd {
    return findDevice
}

func findDevice() tea.Msg {
    locs, err := libfido2.DeviceLocations()
    if err != nil {
        return errorMsg{err: err}
    }

    if len(locs) == 0 {
        return errorMsg{err: fmt.Errorf("no FIDO2 devices found")}
    }

    return deviceFoundMsg{path: locs[0].Path}
}

func registerCredential(devicePath string, pin string) tea.Cmd {
    return func() tea.Msg {
        device, err := libfido2.NewDevice(devicePath)
        if err != nil {
            return errorMsg{err: err}
        }

        challenge := make([]byte, 32)
        rand.Read(challenge)
        cdh := sha256.Sum256(challenge)

        userID := make([]byte, 32)
        rand.Read(userID)

        _, err = device.MakeCredential(
            cdh[:],
            libfido2.RelyingParty{
                ID:   "localhost",
                Name: "FIDO2 Test",
            },
            libfido2.User{
                ID:          userID,
                Name:        "testuser",
                DisplayName: "Test User",
            },
            libfido2.ES256,
            pin,
            &libfido2.MakeCredentialOpts{
                RK: libfido2.True,
            },
        )

        if err != nil {
            return errorMsg{err: err}
        }

        return registrationSuccessMsg{}
    }
}

func waitForTouch(devicePath string, pin string) tea.Cmd {
    return func() tea.Msg {
        device, err := libfido2.NewDevice(devicePath)
        if err != nil {
            return errorMsg{err: err}
        }

        challenge := make([]byte, 32)
        rand.Read(challenge)
        cdh := sha256.Sum256(challenge)

        start := time.Now()

        _, err = device.Assertion(
            "localhost",
            cdh[:],
            nil,
            pin,
            &libfido2.AssertionOpts{
                UP: libfido2.True,
            },
        )

        duration := time.Since(start)

        if err != nil {
            return errorMsg{err: err}
        }

        return touchSuccessMsg{duration: duration}
    }
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "ctrl+c", "q":
            return m, tea.Quit
        case "enter", " ":
            if m.state == stateInit {
                m.state = stateDeviceCheck
                m.logs = append(m.logs, "[System] Starting FIDO2 test...")
                return m, findDevice
            } else if m.state == statePINEntry {
                m.pin = m.pinInput
                if m.pin == "" {
                    m.logs = append(m.logs, "[FIDO2] No PIN - using key without PIN...")
                } else {
                    m.logs = append(m.logs, "[FIDO2] PIN set - registering resident key...")
                }
                m.state = stateRegistering
                return m, registerCredential(m.devicePath, m.pin)
            } else if m.state == stateTouchDetected || m.state == stateError {
                if m.registered {
                    m.testCount++
                    m.state = stateWaitingForTouch
                    m.touchStart = time.Now()
                    m.logs = append(m.logs, fmt.Sprintf("[Test #%d] Authenticating...", m.testCount))
                    return m, waitForTouch(m.devicePath, m.pin)
                } else {
                    m.state = stateDeviceCheck
                    m.logs = append(m.logs, "[System] Restarting...")
                    return m, findDevice
                }
            }
        case "backspace":
            if m.state == statePINEntry && len(m.pinInput) > 0 {
                m.pinInput = m.pinInput[:len(m.pinInput)-1]
            }
        default:
            if m.state == statePINEntry {
                if len(msg.String()) == 1 && msg.String()[0] >= 32 && msg.String()[0] <= 126 {
                    m.pinInput += msg.String()
                }
            }
        }

    case deviceFoundMsg:
        m.devicePath = msg.path
        m.logs = append(m.logs, fmt.Sprintf("[Device] Found: %s", msg.path))
        m.logs = append(m.logs, "[FIDO2] Enter PIN or press ENTER...")
        m.state = statePINEntry
        m.pinInput = ""
        return m, nil

    case registrationSuccessMsg:
        m.registered = true
        m.testCount = 1
        m.logs = append(m.logs, "[SUCCESS] Credential registered!")
        m.logs = append(m.logs, "[Test #1] First authentication...")
        m.state = stateWaitingForTouch
        m.touchStart = time.Now()
        return m, waitForTouch(m.devicePath, m.pin)

    case touchSuccessMsg:
        m.state = stateTouchDetected
        m.touchDuration = msg.duration
        m.logs = append(m.logs, fmt.Sprintf("[SUCCESS] Touch #%d: %.2fs", m.testCount, msg.duration.Seconds()))
        return m, nil

    case errorMsg:
        m.state = stateError
        m.err = msg.err
        m.logs = append(m.logs, fmt.Sprintf("[ERROR] %v", msg.err))
        return m, nil
    }

    return m, nil
}

func (m model) View() string {
    s := titleStyle.Render("🔑 FIDO2 Touch Timing Monitor") + "\n\n"

    switch m.state {
    case stateInit:
        s += normalStyle.Render("Press ENTER to start touch timing tests\n\n")

    case stateDeviceCheck:
        s += warningStyle.Render("⏳ Checking for FIDO2 devices...\n\n")

    case statePINEntry:
        s += normalStyle.Render("Enter PIN (leave empty for no PIN):\n")
        masked := ""
        for range m.pinInput {
            masked += "*"
        }
        s += normalStyle.Render("> " + masked + "\n\n")
        s += normalStyle.Render("Press ENTER to continue\n\n")

    case stateRegistering:
        s += warningStyle.Render("🔴 TOUCH KEY TO REGISTER 🔴\n\n")

    case stateWaitingForTouch:
        elapsed := time.Since(m.touchStart).Seconds()
        s += errorStyle.Render(fmt.Sprintf("🔴 TOUCH #%d - TOUCH NOW! 🔴", m.testCount)) + "\n"
        s += warningStyle.Render(fmt.Sprintf("⏱️  %.1fs\n\n", elapsed))

    case stateTouchDetected:
        s += successStyle.Render(fmt.Sprintf("✅ Touch #%d: %.2fs\n\n", m.testCount, m.touchDuration.Seconds()))
        s += normalStyle.Render("Press ENTER to test again (hammer it!)\n\n")

    case stateError:
        s += errorStyle.Render(fmt.Sprintf("❌ %v\n\n", m.err))
        s += normalStyle.Render("Press ENTER to retry\n\n")
    }

    s += lipgloss.NewStyle().
        Foreground(lipgloss.Color("240")).
        Render("--- Timing Log ---\n")

    start := 0
    if len(m.logs) > 10 {
        start = len(m.logs) - 10
    }
    for _, log := range m.logs[start:] {
        s += normalStyle.Render(log + "\n")
    }

    s += "\n" + normalStyle.Render("'q' to quit")

    return s
}

func main() {
    p := tea.NewProgram(initialModel())
    if _, err := p.Run(); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
}
