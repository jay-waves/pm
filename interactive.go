package main

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"charm.land/huh/v2"
)

var errCancelled = errors.New("operation cancelled")

const (
	maxSecretLength   = 1024
	maxIdentityLength = 512
	maxNotesLength    = 4096
)

func runAddForm() (Entry, error) {
	var secret, confirmation, identity, expires, notes string
	save := true
	form := huh.NewForm(
		huh.NewGroup(
			secretInput("Secret", &secret, true),
			secretConfirmationInput(&confirmation, func() string { return secret }),
			huh.NewInput().
				Title("Identity").
				CharLimit(maxIdentityLength).
				Validate(validateIdentity).
				Value(&identity),
			huh.NewInput().
				Title("Expires at").
				Description("YYYY-MM-DD; leave empty for no expiration").
				Validate(validateOptionalDate).
				Value(&expires),
			safeNotesField(&notes),
			huh.NewConfirm().
				Title("Save this entry?").
				Affirmative("Save").
				Negative("Cancel").
				Value(&save),
		),
	)
	if err := runForm(form); err != nil {
		return Entry{}, err
	}
	if !save {
		return Entry{}, errCancelled
	}
	entry := newEntry()
	entry.Secret = secret
	entry.Identity = identity
	entry.Notes = notes
	if expires != "" {
		entry.ExpiresAt = &expires
	}
	return entry, nil
}

func runEditForm(name string, entry Entry) (Entry, error) {
	dirty := false
	secretChanged := false
	for {
		action := ""
		options := []huh.Option[string]{
			huh.NewOption("Identity   "+fieldSummary(entry.Identity, 48), "identity"),
			huh.NewOption(
				"Secret     "+map[bool]string{false: "(unchanged)", true: "(replacement entered)"}[secretChanged],
				"secret"),
			huh.NewOption("Expires    "+expirationSummary(entry.ExpiresAt), "expires"),
			huh.NewOption("Notes      "+notesSummary(entry.Notes), "notes"),
			huh.NewOption("Save", "save"),
			huh.NewOption("Cancel", "cancel"),
		}
		if err := runField(
			huh.NewSelect[string]().
				Title("Edit " + name).
				Options(options...).
				Value(&action)); err != nil {
			return Entry{}, err
		}

		switch action {
		case "identity":
			value := entry.Identity
			if err := runField(huh.NewInput().
				Title("Identity").
				CharLimit(maxIdentityLength).
				Validate(validateIdentity).
				Value(&value)); err != nil {
				return Entry{}, err
			}
			if value != entry.Identity {
				entry.Identity = value
				dirty = true
			}
		case "secret":
			var value, confirmation string
			form := huh.NewForm(huh.NewGroup(
				secretInput("New secret", &value, true),
				secretConfirmationInput(&confirmation, func() string { return value }),
			))
			if err := runForm(form); err != nil {
				return Entry{}, err
			}
			entry.Secret = value
			secretChanged = true
			dirty = true
		case "expires":
			value := ""
			if entry.ExpiresAt != nil {
				value = *entry.ExpiresAt
			}
			if err := runField(huh.NewInput().
				Title("Expires at").
				Description("YYYY-MM-DD; leave empty for no expiration").
				Validate(validateOptionalDate).
				Value(&value)); err != nil {
				return Entry{}, err
			}
			if value == "" {
				if entry.ExpiresAt != nil {
					entry.ExpiresAt = nil
					dirty = true
				}
			} else if entry.ExpiresAt == nil || *entry.ExpiresAt != value {
				entry.ExpiresAt = &value
				dirty = true
			}
		case "notes":
			value := entry.Notes
			if err := runField(safeNotesField(&value)); err != nil {
				return Entry{}, err
			}
			if value != entry.Notes {
				entry.Notes = value
				dirty = true
			}
		case "save":
			if !dirty {
				return Entry{}, errCancelled
			}
			confirm := true
			if err := runField(huh.NewConfirm().
				Title("Save changes?").
				Affirmative("Save").
				Negative("Back").
				Value(&confirm)); err != nil {
				return Entry{}, err
			}
			if confirm {
				entry.ModifiedAt = today()
				return entry, nil
			}
		case "cancel":
			if !dirty {
				return Entry{}, errCancelled
			}
			discard := false
			if err := runField(huh.NewConfirm().
				Title("Discard unsaved changes?").
				Affirmative("Discard").
				Negative("Back").
				Value(&discard)); err != nil {
				return Entry{}, err
			}
			if discard {
				return Entry{}, errCancelled
			}
		}
	}
}

func secretInput(title string, value *string, required bool) *huh.Input {
	field := huh.NewInput().
		Title(title).
		EchoMode(huh.EchoModeNone).
		CharLimit(maxSecretLength).
		Value(value)
	if required {
		field.Validate(func(input string) error {
			if input == "" {
				return errors.New("secret cannot be empty")
			}
			return validateNoUnsafeControls(input, false)
		})
	}
	return field
}

func secretConfirmationInput(value *string, expected func() string) *huh.Input {
	return huh.NewInput().
		Title("Confirm secret").
		EchoMode(huh.EchoModeNone).
		CharLimit(maxSecretLength).
		Validate(func(input string) error {
			if input != expected() {
				return errors.New("secrets do not match")
			}
			return nil
		}).
		Value(value)
}

func safeNotesField(value *string) *huh.Text {
	return huh.NewText().
		Title("Notes").
		CharLimit(maxNotesLength).
		ExternalEditor(false).
		Validate(validateNotes).
		Value(value)
}

func runForm(form *huh.Form) error {
	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errCancelled
		}
		return err
	}
	return nil
}

func runField(field huh.Field) error {
	if err := huh.Run(field); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errCancelled
		}
		return err
	}
	return nil
}

func validateIdentity(value string) error {
	if utf8.RuneCountInString(value) > maxIdentityLength {
		return fmt.Errorf("identity cannot exceed %d characters", maxIdentityLength)
	}
	return validateNoUnsafeControls(value, false)
}

func validateNotes(value string) error {
	if utf8.RuneCountInString(value) > maxNotesLength {
		return fmt.Errorf("notes cannot exceed %d characters", maxNotesLength)
	}
	return validateNoUnsafeControls(value, true)
}

func validateOptionalDate(value string) error {
	if value == "" || validDate(value) {
		return nil
	}
	return errors.New("expected YYYY-MM-DD or an empty value")
}

func validateNoUnsafeControls(value string, allowWhitespace bool) error {
	for _, character := range value {
		if character == '\x1b' || character == '\x7f' {
			return errors.New("terminal control characters are not allowed")
		}
		if unicode.IsControl(character) {
			if allowWhitespace && (character == '\n' || character == '\t') {
				continue
			}
			return errors.New("control characters are not allowed")
		}
	}
	return nil
}

func fieldSummary(value string, limit int) string {
	if value == "" {
		return "-"
	}
	value = strings.ReplaceAll(value, "\n", " ")
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit-1]) + "…"
	}
	return value
}

func expirationSummary(value *string) string {
	if value == nil {
		return "never"
	}
	return *value
}

func notesSummary(value string) string {
	if value == "" {
		return "-"
	}
	return fmt.Sprintf("%d line(s)", strings.Count(value, "\n")+1)
}
