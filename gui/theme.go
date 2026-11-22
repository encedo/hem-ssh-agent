package main

// The Encedo palette, taken from encedo-wg-hsm's gui/theme.go (MIT, same
// author) so the two windows look like one product: a ground, a surface,
// three weights of ink, a rule, and two semantic colours - "sealed" (green:
// inside the HEM, ready) and "exposed" (rust: failure).

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type encedoTheme struct {
	variant variantChoice // variantAuto follows the desktop
}

type variantChoice int

const (
	variantAuto variantChoice = iota
	variantLight
	variantDark
)

// themeFor turns -theme into a theme. An unknown name is refused rather than
// silently falling back to the desktop's choice.
func themeFor(name string) (encedoTheme, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto", "system":
		return encedoTheme{}, nil
	case "dark":
		return encedoTheme{variant: variantDark}, nil
	case "light":
		return encedoTheme{variant: variantLight}, nil
	}
	return encedoTheme{}, fmt.Errorf("unknown theme %q: expected auto, dark or light", name)
}

var _ fyne.Theme = encedoTheme{}

var (
	lightPalette = palette{
		ground:  rgb(0xF1, 0xF4, 0xF3),
		surface: rgb(0xFF, 0xFF, 0xFF),
		sunken:  rgb(0xE7, 0xEB, 0xE9),
		ink:     rgb(0x0F, 0x14, 0x14),
		inkSoft: rgb(0x3A, 0x47, 0x46),
		muted:   rgb(0x6A, 0x77, 0x73),
		rule:    rgb(0xD5, 0xDC, 0xD9),
		sealed:  rgb(0x0F, 0x5F, 0x4B),
		exposed: rgb(0x94, 0x42, 0x2A),
		warning: rgb(0x8A, 0x63, 0x20),
		onDark:  rgb(0xF2, 0xF8, 0xF5),
	}
	darkPalette = palette{
		ground:  rgb(0x0A, 0x0E, 0x0E),
		surface: rgb(0x12, 0x19, 0x18),
		sunken:  rgb(0x06, 0x09, 0x09),
		ink:     rgb(0xE8, 0xF0, 0xED),
		inkSoft: rgb(0xAF, 0xBD, 0xB8),
		muted:   rgb(0x7C, 0x8C, 0x87),
		rule:    rgb(0x23, 0x2D, 0x2C),
		sealed:  rgb(0x47, 0xC6, 0xA3),
		exposed: rgb(0xDE, 0x84, 0x67),
		warning: rgb(0xD9, 0xA8, 0x5A),
		onDark:  rgb(0x06, 0x09, 0x09),
	}
)

type palette struct {
	ground, surface, sunken   color.Color
	ink, inkSoft, muted, rule color.Color
	sealed, exposed, warning  color.Color
	onDark                    color.Color
}

func rgb(r, g, b uint8) color.Color { return color.NRGBA{R: r, G: g, B: b, A: 255} }

func alpha(c color.Color, a uint8) color.Color {
	r, g, b, _ := c.RGBA()
	return color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: a}
}

func (t encedoTheme) Color(name fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch t.variant {
	case variantLight:
		v = theme.VariantLight
	case variantDark:
		v = theme.VariantDark
	}
	p := darkPalette
	if v == theme.VariantLight {
		p = lightPalette
	}
	switch name {
	case theme.ColorNameBackground:
		return p.ground
	case theme.ColorNameForeground:
		return p.ink
	case theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnSuccess:
		return p.onDark
	case theme.ColorNamePrimary, theme.ColorNameSuccess:
		return p.sealed
	case theme.ColorNameError:
		return p.exposed
	case theme.ColorNameWarning:
		return p.warning
	case theme.ColorNameDisabled, theme.ColorNamePlaceHolder:
		return p.muted
	case theme.ColorNameSeparator:
		return p.rule
	case theme.ColorNameInputBackground, theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground:
		return p.surface
	case theme.ColorNameInputBorder, theme.ColorNameDisabledButton:
		return p.rule
	case theme.ColorNameButton:
		return p.sunken
	case theme.ColorNameHover:
		return alpha(p.sealed, 28)
	case theme.ColorNameFocus, theme.ColorNameSelection:
		return alpha(p.sealed, 64)
	case theme.ColorNameScrollBar:
		return alpha(p.muted, 120)
	case theme.ColorNameShadow:
		return color.NRGBA{A: 60}
	}
	return theme.DefaultTheme().Color(name, v)
}

func (encedoTheme) Font(s fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(s) }

func (encedoTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }

func (encedoTheme) Size(n fyne.ThemeSizeName) float32 { return theme.DefaultTheme().Size(n) }
