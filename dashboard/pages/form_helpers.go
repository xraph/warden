package pages

import "github.com/a-h/templ"

// htmxFormAttrs produces form attributes for an HTMX form that closes a dialog on success.
func htmxFormAttrs(endpoint, method, errTarget, dialogID, reloadURL string) templ.Attributes {
	attrs := templ.Attributes{
		"hx-ext":    "json-enc",
		"hx-target": errTarget,
		"hx-swap":   "innerHTML",
	}
	switch method {
	case "put":
		attrs["hx-put"] = endpoint
	case "delete":
		attrs["hx-delete"] = endpoint
	default:
		attrs["hx-post"] = endpoint
	}
	afterRequest := "if(event.detail.successful) {"
	if dialogID != "" {
		afterRequest += " tuiCloseDialog('" + dialogID + "');"
	}
	afterRequest += " htmx.ajax('GET', '" + reloadURL + "', {target:'#content'}); }"
	attrs["hx-on::after-request"] = afterRequest
	return attrs
}
