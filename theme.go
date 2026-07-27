package main

import (
	"os"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

var formTheme huh.Theme = huh.ThemeFunc(formStyles)

func formStyles(isDark bool) *huh.Styles {
	styles := huh.ThemeBase16(isDark)
	accent := lipgloss.Color("6")

	styles.FieldSeparator = lipgloss.NewStyle().SetString("\n")

	// Huh Input reads the cursor foreground, while Huh Text reads its
	// background. Set both to avoid an uncolored textarea cursor.
	styles.Focused.TextInput.Cursor = lipgloss.NewStyle().
		Foreground(accent).
		Background(accent)
	styles.Blurred.TextInput.Cursor = styles.Focused.TextInput.Cursor
	return styles
}

type cliTheme struct {
	enabled bool
	text    lipgloss.Style
	muted   lipgloss.Style
	accent  lipgloss.Style
	success lipgloss.Style
	warning lipgloss.Style
	danger  lipgloss.Style
}

func cliThemeFor(file *os.File) cliTheme {
	if !colorOutputEnabled(file) {
		return cliTheme{}
	}
	return cliTheme{
		enabled: true,
		text:    lipgloss.NewStyle(),
		muted:   lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
		accent:  lipgloss.NewStyle().Foreground(lipgloss.Color("6")),
		success: lipgloss.NewStyle().Foreground(lipgloss.Color("2")),
		warning: lipgloss.NewStyle().Foreground(lipgloss.Color("3")),
		danger:  lipgloss.NewStyle().Foreground(lipgloss.Color("1")),
	}
}

func (theme cliTheme) strong(style lipgloss.Style, value string) string {
	if !theme.enabled {
		return value
	}
	return style.Bold(true).Render(value)
}

func formatUsageOutput(value string, theme cliTheme) string {
	if !theme.enabled {
		return value
	}
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		switch {
		case index == 0:
			lines[index] = theme.strong(theme.accent, line)
		case strings.HasSuffix(line, ":"):
			lines[index] = theme.accent.Render(line)
		case strings.HasPrefix(line, "  "):
			lines[index] = theme.text.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}
