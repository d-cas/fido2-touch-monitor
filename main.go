package main

import (
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "os"
    "strings"

    tea "github.com/charmbracelet/bubbletea"
    "github.com/charmbracelet/lipgloss"
    "github.com/keys-pub/go-libfido2"
)


var (
    errorStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("196")).
        Bold(true)

    successStyle = lipgloss.NewStyle().
        Foreground(lipgloss.Color("46")).
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
    state      state
    devicePath string
    err        error
    registered bool
    pin        string
    pinInput   string
}

type deviceFoundMsg struct {
    path string
}

type registrationSuccessMsg struct{}

type touchSuccessMsg struct{}

type errorMsg struct {
    err error
}

func initialModel() model {
    return model{
        state: stateInit,
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

        _, err = device.Assertion(
            "localhost",
            cdh[:],
            nil,
            pin,
            &libfido2.AssertionOpts{
                UP: libfido2.True,
            },
        )

        if err != nil {
            return errorMsg{err: err}
        }

        return touchSuccessMsg{}
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
                return m, findDevice
            } else if m.state == statePINEntry {
                m.pin = m.pinInput
                m.state = stateRegistering
                return m, registerCredential(m.devicePath, m.pin)
            } else if m.state == stateTouchDetected || m.state == stateError {
                if m.registered {
                    m.state = stateWaitingForTouch
                    return m, waitForTouch(m.devicePath, m.pin)
                } else {
                    m.state = stateDeviceCheck
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
        m.state = statePINEntry
        m.pinInput = ""
        return m, nil

    case registrationSuccessMsg:
        m.registered = true
        m.state = stateWaitingForTouch
        return m, waitForTouch(m.devicePath, m.pin)

    case touchSuccessMsg:
        m.state = stateTouchDetected
        return m, nil

    case errorMsg:
        // Check if it's a "no credentials" error (key was swapped)
        if strings.Contains(msg.err.Error(), "no credentials") {
            // Key was swapped - reset and re-register
            m.registered = false
            m.state = stateDeviceCheck
            return m, findDevice
        }
        m.state = stateError
        m.err = msg.err
        return m, nil
    }

    return m, nil
}

func (m model) View() string {
    s := normalStyle.Render("🔑 FIDO2 Touch Monitor\n\n")

    switch m.state {
    case stateInit:
        s += normalStyle.Render("Press ENTER to start\n\n")

    case stateDeviceCheck:
        s += normalStyle.Render("⏳ Checking for FIDO2 devices...\n\n")

    case statePINEntry:
        s += normalStyle.Render("Enter PIN (leave empty for no PIN):\n")
        masked := ""
        for range m.pinInput {
            masked += "*"
        }
        s += normalStyle.Render("> " + masked + "\n\n")
        s += normalStyle.Render("Press ENTER to continue\n\n")

    case stateRegistering:
        s += normalStyle.Render("🔴 TOUCH KEY TO REGISTER 🔴\n\n")

    case stateWaitingForTouch:
        s += errorStyle.Render("🔴 TOUCH NOW! 🔴\n\n")

    case stateTouchDetected:
        s += successStyle.Render("✅ Touch detected!\n\n")
        s += normalStyle.Render("Press ENTER to test again\n\n")

    case stateError:
        s += errorStyle.Render(fmt.Sprintf("❌ %v\n\n", m.err))
        s += normalStyle.Render("Press ENTER to retry\n\n")
    }

    s += normalStyle.Render("'q' to quit")

    return s
}

func main() {
    p := tea.NewProgram(initialModel())
    if _, err := p.Run(); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
}
