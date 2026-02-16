package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"sshproxy/pkg/storage"
)

type viewMode int
type filterState int

const (
	viewListing viewMode = iota
	viewLogs
)

const (
	filterAll filterState = iota
	filterAllowed
	filterBlocked
)

type model struct {
	repo          *storage.Repository
	table         table.Model
	mode          viewMode
	filter        filterState
	limit         int
	summaries     []storage.HASSHSummary
	connections   []storage.ConnectionDetail
	selected      map[string]bool // Map by HASSH fingerprint (listing) or ID (logs)
	searchMode    bool
	searchInput   textinput.Model
	searchField   string
	err           error
	statusMessage string
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second*5, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func Run(repo *storage.Repository, limit int) error {
	m := newModel(repo, limit)

	p := tea.NewProgram(&m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func newModel(repo *storage.Repository, limit int) model {
	// Start with listing columns
	columns := []table.Column{
		{Title: "HASSH", Width: 32},
		{Title: "Banner", Width: 45},
		{Title: "IPs", Width: 6},
		{Title: "Conns", Width: 8},
		{Title: "Last Seen", Width: 19},
		{Title: "Blocked", Width: 7},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(20),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	searchInput := textinput.New()
	searchInput.Placeholder = "Search..."
	searchInput.CharLimit = 100

	m := model{
		repo:        repo,
		table:       t,
		mode:        viewListing,
		filter:      filterAll,
		limit:       limit,
		selected:    make(map[string]bool),
		searchInput: searchInput,
		searchField: "hassh",
	}

	m.refreshData()
	return m
}

func (m *model) switchView(newMode viewMode) {
	if m.mode == newMode {
		return
	}

	m.mode = newMode
	m.filter = filterAll
	m.selected = make(map[string]bool)

	// Update table columns based on view
	if m.mode == viewListing {
		m.table.SetColumns([]table.Column{
			{Title: "HASSH", Width: 32},
			{Title: "Banner", Width: 45},
			{Title: "IPs", Width: 6},
			{Title: "Conns", Width: 8},
			{Title: "Last Seen", Width: 19},
			{Title: "Blocked", Width: 7},
		})
		m.searchField = "hassh"
	} else {
		m.table.SetColumns([]table.Column{
			{Title: "ID", Width: 8},
			{Title: "Timestamp", Width: 19},
			{Title: "IP Address", Width: 15},
			{Title: "HASSH", Width: 32},
			{Title: "Banner", Width: 40},
			{Title: "Blocked", Width: 7},
		})
		m.searchField = "ip"
	}

	m.refreshData()
}

func (m *model) refreshData() {
	var blocked *bool
	switch m.filter {
	case filterAllowed:
		b := false
		blocked = &b
	case filterBlocked:
		b := true
		blocked = &b
	case filterAll:
		blocked = nil
	}

	if m.mode == viewListing {
		summaries, err := m.repo.ListHASSHSummaries(m.limit, blocked, "last_seen", true)
		if err != nil {
			m.err = err
			return
		}
		m.summaries = summaries
		m.updateListingTable()
	} else {
		connections, err := m.repo.ListConnections(m.limit, blocked, "timestamp", true)
		if err != nil {
			m.err = err
			return
		}
		m.connections = connections
		m.updateLogsTable()
	}
}

func (m *model) updateListingTable() {
	rows := make([]table.Row, len(m.summaries))
	for i, s := range m.summaries {
		blocked := "no"
		if s.Blocked {
			blocked = "YES"
		}

		prefix := "  "
		if m.selected[s.HASSHFingerprint] {
			prefix = "✓ "
		}

		banner := s.SSHClientBanner
		if len(banner) > 42 {
			banner = banner[:39] + "..."
		}

		rows[i] = table.Row{
			prefix + s.HASSHFingerprint,
			banner,
			fmt.Sprintf("%d", s.IPCount),
			fmt.Sprintf("%d", s.TotalConnections),
			s.LastSeen.Format("2006-01-02 15:04:05"),
			blocked,
		}
	}
	m.table.SetRows(rows)
}

func (m *model) updateLogsTable() {
	rows := make([]table.Row, len(m.connections))
	for i, c := range m.connections {
		blocked := "no"
		if c.Blocked {
			blocked = "YES"
		}

		prefix := "  "
		connID := fmt.Sprintf("%d", c.ID)
		if m.selected[connID] {
			prefix = "✓ "
		}

		banner := c.SSHClientBanner
		if len(banner) > 37 {
			banner = banner[:34] + "..."
		}

		rows[i] = table.Row{
			prefix + connID,
			c.Timestamp.Format("2006-01-02 15:04:05"),
			c.IPAddress,
			c.HASSHFingerprint,
			banner,
			blocked,
		}
	}
	m.table.SetRows(rows)
}

func (m *model) Init() tea.Cmd {
	return tickCmd()
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.searchMode {
			return m.handleSearchKeys(msg)
		}
		return m.handleNormalKeys(msg)

	case tickMsg:
		m.refreshData()
		return m, tickCmd()

	case tea.WindowSizeMsg:
		m.table.SetHeight(msg.Height - 10)
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) handleNormalKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "v":
		// Toggle between listing and logs view
		if m.mode == viewListing {
			m.switchView(viewLogs)
			m.statusMessage = "Switched to Logs view"
		} else {
			m.switchView(viewListing)
			m.statusMessage = "Switched to Listing view"
		}

	case "tab":
		// Cycle through filter tabs
		m.filter = (m.filter + 1) % 3
		m.refreshData()
		filterNames := []string{"all", "allowed", "blocked"}
		m.statusMessage = fmt.Sprintf("Filter: %s", filterNames[m.filter])

	case "shift+tab":
		// Cycle backwards through filter tabs
		m.filter = (m.filter + 2) % 3
		m.refreshData()
		filterNames := []string{"all", "allowed", "blocked"}
		m.statusMessage = fmt.Sprintf("Filter: %s", filterNames[m.filter])

	case " ":
		// Toggle selection
		if m.mode == viewListing {
			if m.table.Cursor() < len(m.summaries) {
				hassh := m.summaries[m.table.Cursor()].HASSHFingerprint
				m.selected[hassh] = !m.selected[hassh]
				m.updateListingTable()
			}
		} else {
			if m.table.Cursor() < len(m.connections) {
				connID := fmt.Sprintf("%d", m.connections[m.table.Cursor()].ID)
				m.selected[connID] = !m.selected[connID]
				m.updateLogsTable()
			}
		}

	case "b":
		// Block selected (only in listing view)
		if m.mode == viewListing {
			*m = m.blockSelected()
		} else {
			*m = m.blockSelectedFromLogs()
		}
		return m, nil

	case "u":
		// Unblock selected
		if m.mode == viewListing {
			*m = m.unblockSelected()
		} else {
			*m = m.unblockSelectedFromLogs()
		}
		return m, nil

	case "c":
		// Clear selection
		m.selected = make(map[string]bool)
		if m.mode == viewListing {
			m.updateListingTable()
		} else {
			m.updateLogsTable()
		}
		m.statusMessage = "Selection cleared"

	case "/":
		// Enter search mode
		m.searchMode = true
		m.searchInput.Focus()
		if m.mode == viewListing {
			m.statusMessage = "Search mode: hassh or banner (TAB to switch, ESC to cancel)"
		} else {
			m.statusMessage = "Search mode: ip, hassh, or banner (TAB to switch, ESC to cancel)"
		}

	case "r":
		// Refresh
		m.refreshData()
		m.statusMessage = "Refreshed"
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m *model) handleSearchKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.Type {
	case tea.KeyEsc:
		m.searchMode = false
		m.searchInput.Blur()
		m.searchInput.SetValue("")
		m.statusMessage = ""
		return m, nil

	case tea.KeyEnter:
		// Perform search
		query := m.searchInput.Value()
		if query != "" {
			m.performSearch(query)
		}
		m.searchMode = false
		m.searchInput.Blur()
		m.searchInput.SetValue("")
		return m, nil

	case tea.KeyTab:
		// Cycle search field based on current view
		if m.mode == viewListing {
			if m.searchField == "hassh" {
				m.searchField = "banner"
			} else {
				m.searchField = "hassh"
			}
		} else {
			// Logs view: cycle ip -> hassh -> banner -> ip
			switch m.searchField {
			case "ip":
				m.searchField = "hassh"
			case "hassh":
				m.searchField = "banner"
			case "banner":
				m.searchField = "ip"
			}
		}
		m.statusMessage = fmt.Sprintf("Search by: %s (ESC to cancel)", m.searchField)
	}

	m.searchInput, cmd = m.searchInput.Update(msg)
	return m, cmd
}

func (m *model) performSearch(query string) {
	if m.mode == viewListing {
		var hassh, banner string
		switch m.searchField {
		case "hassh":
			hassh = query
		case "banner":
			banner = query
		}

		summaries, err := m.repo.SearchHASSHSummaries(hassh, banner, m.limit)
		if err != nil {
			m.err = err
			m.statusMessage = fmt.Sprintf("Search failed: %v", err)
			return
		}

		m.summaries = summaries
		m.updateListingTable()
		m.statusMessage = fmt.Sprintf("Found %d results for '%s'", len(summaries), query)
	} else {
		var ip, hassh, banner string
		switch m.searchField {
		case "ip":
			ip = query
		case "hassh":
			hassh = query
		case "banner":
			banner = query
		}

		connections, err := m.repo.SearchConnections(ip, hassh, banner, m.limit)
		if err != nil {
			m.err = err
			m.statusMessage = fmt.Sprintf("Search failed: %v", err)
			return
		}

		m.connections = connections
		m.updateLogsTable()
		m.statusMessage = fmt.Sprintf("Found %d results for '%s'", len(connections), query)
	}
}

func (m *model) blockSelected() model {
	if len(m.selected) == 0 {
		m.statusMessage = "No fingerprints selected"
		return *m
	}

	count := 0
	errors := []string{}

	for hassh, selected := range m.selected {
		if !selected {
			continue
		}

		if err := m.repo.BlockHASH(hassh, "tui_block"); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", hassh[:8], err))
		} else {
			count++
		}
	}

	m.selected = make(map[string]bool)
	m.refreshData()

	if len(errors) > 0 {
		m.statusMessage = fmt.Sprintf("Blocked %d, errors: %s", count, strings.Join(errors, ", "))
	} else {
		m.statusMessage = fmt.Sprintf("Blocked %d HASSH fingerprint(s). Run 'sshctl reload' on proxy.", count)
	}

	return *m
}

func (m *model) blockSelectedFromLogs() model {
	if len(m.selected) == 0 {
		m.statusMessage = "No connections selected"
		return *m
	}

	// Extract unique HASSH fingerprints from selected connections
	hasshSet := make(map[string]bool)
	for connID, selected := range m.selected {
		if !selected {
			continue
		}

		// Find the connection by ID
		for _, conn := range m.connections {
			if fmt.Sprintf("%d", conn.ID) == connID {
				hasshSet[conn.HASSHFingerprint] = true
				break
			}
		}
	}

	count := 0
	errors := []string{}

	for hassh := range hasshSet {
		if err := m.repo.BlockHASH(hassh, "tui_block_from_log"); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", hassh[:8], err))
		} else {
			count++
		}
	}

	m.selected = make(map[string]bool)
	m.refreshData()

	if len(errors) > 0 {
		m.statusMessage = fmt.Sprintf("Blocked %d HASSH(s), errors: %s", count, strings.Join(errors, ", "))
	} else {
		m.statusMessage = fmt.Sprintf("Blocked %d unique HASSH fingerprint(s). Run 'sshctl reload' on proxy.", count)
	}

	return *m
}

func (m *model) unblockSelected() model {
	if len(m.selected) == 0 {
		m.statusMessage = "No fingerprints selected"
		return *m
	}

	count := 0
	errors := []string{}

	for hassh, selected := range m.selected {
		if !selected {
			continue
		}

		if err := m.repo.UnblockHASH(hassh); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", hassh[:8], err))
		} else {
			count++
		}
	}

	m.selected = make(map[string]bool)
	m.refreshData()

	if len(errors) > 0 {
		m.statusMessage = fmt.Sprintf("Unblocked %d, errors: %s", count, strings.Join(errors, ", "))
	} else {
		m.statusMessage = fmt.Sprintf("Unblocked %d HASSH fingerprint(s). Run 'sshctl reload' on proxy.", count)
	}

	return *m
}

func (m *model) unblockSelectedFromLogs() model {
	if len(m.selected) == 0 {
		m.statusMessage = "No connections selected"
		return *m
	}

	// Extract unique HASSH fingerprints from selected connections
	hasshSet := make(map[string]bool)
	for connID, selected := range m.selected {
		if !selected {
			continue
		}

		// Find the connection by ID
		for _, conn := range m.connections {
			if fmt.Sprintf("%d", conn.ID) == connID {
				hasshSet[conn.HASSHFingerprint] = true
				break
			}
		}
	}

	count := 0
	errors := []string{}

	for hassh := range hasshSet {
		if err := m.repo.UnblockHASH(hassh); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", hassh[:8], err))
		} else {
			count++
		}
	}

	m.selected = make(map[string]bool)
	m.refreshData()

	if len(errors) > 0 {
		m.statusMessage = fmt.Sprintf("Unblocked %d HASSH(s), errors: %s", count, strings.Join(errors, ", "))
	} else {
		m.statusMessage = fmt.Sprintf("Unblocked %d unique HASSH fingerprint(s). Run 'sshctl reload' on proxy.", count)
	}

	return *m
}

func (m *model) View() string {
	var b strings.Builder

	// Title with current view
	viewName := "Fingerprint Listing"
	if m.mode == viewLogs {
		viewName = "Connection Logs"
	}

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Render(fmt.Sprintf("SSH Proxy Manager - %s", viewName))

	b.WriteString(title + "\n\n")

	// Filter tabs
	activeTab := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Padding(0, 1)

	inactiveTab := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Padding(0, 1)

	tabs := []string{}
	filterNames := []string{"All", "Allowed", "Blocked"}
	for i, name := range filterNames {
		if filterState(i) == m.filter {
			tabs = append(tabs, activeTab.Render(name))
		} else {
			tabs = append(tabs, inactiveTab.Render(name))
		}
	}
	b.WriteString(strings.Join(tabs, " | ") + "\n\n")

	// Table
	b.WriteString(m.table.View() + "\n\n")

	// Search input
	if m.searchMode {
		b.WriteString(fmt.Sprintf("Search by %s: %s\n\n", m.searchField, m.searchInput.View()))
	}

	// Status message
	if m.statusMessage != "" {
		status := lipgloss.NewStyle().
			Foreground(lipgloss.Color("170")).
			Render(m.statusMessage)
		b.WriteString(status + "\n")
	}

	// Error display
	if m.err != nil {
		errMsg := lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Render(fmt.Sprintf("Error: %v", m.err))
		b.WriteString(errMsg + "\n")
	}

	// Help
	help := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Render("v: switch view | tab: filter | space: select | b: block | u: unblock | c: clear | /: search | r: refresh | q: quit")
	b.WriteString("\n" + help)

	return b.String()
}
