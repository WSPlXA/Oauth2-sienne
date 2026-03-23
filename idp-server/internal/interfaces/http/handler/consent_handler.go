package handler

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	appconsent "idp-server/internal/application/consent"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type ConsentHandler struct {
	service appconsent.Manager
}

func NewConsentHandler(service appconsent.Manager) *ConsentHandler {
	return &ConsentHandler{service: service}
}

func (h *ConsentHandler) Handle(c *gin.Context) {
	sessionID, _ := c.Cookie("idp_session")

	if c.Request.Method == http.MethodGet {
		returnTo := c.Query("return_to")
		result, err := h.service.Prepare(c.Request.Context(), appconsent.PrepareInput{
			ReturnTo:  returnTo,
			SessionID: sessionID,
		})
		if err != nil {
			h.writeError(c, err, returnTo)
			return
		}

		if wantsHTML(c.GetHeader("Accept")) {
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Status(http.StatusOK)
			_ = consentPageTemplate.Execute(c.Writer, map[string]any{
				"ClientID":   result.ClientID,
				"ClientName": result.ClientName,
				"Scopes":     result.Scopes,
				"ReturnTo":   result.ReturnTo,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"endpoint":    "consent",
			"client_id":   result.ClientID,
			"client_name": result.ClientName,
			"scopes":      result.Scopes,
			"return_to":   result.ReturnTo,
			"message":     "submit action=accept or action=deny",
		})
		return
	}

	var req dto.ConsentDecisionRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid consent request"})
		return
	}

	result, err := h.service.Decide(c.Request.Context(), appconsent.DecideInput{
		ReturnTo:  req.ReturnTo,
		SessionID: sessionID,
		Action:    req.Action,
	})
	if err != nil {
		h.writeError(c, err, req.ReturnTo)
		return
	}

	c.Redirect(http.StatusFound, result.RedirectURI)
}

func wantsHTML(accept string) bool {
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

var consentPageTemplate = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Consent</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f3ea;
      --card: #fffdf8;
      --ink: #1f2a2e;
      --muted: #5f6b6f;
      --line: #d8cdb7;
      --accent: #0f766e;
      --accent-2: #b45309;
      --danger: #b91c1c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      background:
        radial-gradient(circle at top left, rgba(180,83,9,0.10), transparent 30%),
        radial-gradient(circle at bottom right, rgba(15,118,110,0.12), transparent 35%),
        var(--bg);
      color: var(--ink);
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .card {
      width: min(100%, 760px);
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: 0 24px 60px rgba(31,42,46,0.08);
      overflow: hidden;
    }
    .hero {
      padding: 28px 28px 20px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(15,118,110,0.08), rgba(180,83,9,0.08));
    }
    .eyebrow {
      margin: 0 0 10px;
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--accent-2);
    }
    h1 {
      margin: 0;
      font-size: clamp(30px, 5vw, 44px);
      line-height: 1;
      font-weight: 600;
    }
    .sub {
      margin: 12px 0 0;
      color: var(--muted);
      font-size: 17px;
      line-height: 1.6;
    }
    .body {
      padding: 28px;
      display: grid;
      gap: 24px;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 20px;
      background: rgba(255,255,255,0.7);
    }
    .label {
      display: block;
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 8px;
    }
    .value {
      font-size: 22px;
      font-weight: 600;
    }
    ul {
      margin: 0;
      padding-left: 20px;
      display: grid;
      gap: 8px;
    }
    li { line-height: 1.5; }
    .actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 14px 22px;
      font-size: 16px;
      cursor: pointer;
      transition: transform 120ms ease, opacity 120ms ease;
    }
    button:hover { transform: translateY(-1px); }
    .accept {
      background: var(--accent);
      color: white;
    }
    .deny {
      background: white;
      color: var(--danger);
      border: 1px solid rgba(185,28,28,0.25);
    }
    .foot {
      color: var(--muted);
      font-size: 14px;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <main class="card">
    <section class="hero">
      <p class="eyebrow">Authorization Request</p>
      <h1>Review Access</h1>
      <p class="sub">{{.ClientName}} wants permission to access your account.</p>
    </section>
    <section class="body">
      <div class="panel">
        <span class="label">Client</span>
        <div class="value">{{.ClientName}}</div>
        <div class="foot">Client ID: {{.ClientID}}</div>
      </div>
      <div class="panel">
        <span class="label">Requested Scopes</span>
        <ul>
          {{range .Scopes}}<li>{{.}}</li>{{end}}
        </ul>
      </div>
      <form method="post" class="actions">
        <input type="hidden" name="return_to" value="{{.ReturnTo}}">
        <button class="accept" type="submit" name="action" value="accept">Allow Access</button>
        <button class="deny" type="submit" name="action" value="deny">Deny</button>
      </form>
      <p class="foot">Choosing allow will record consent for this client and return you to the OAuth authorization flow.</p>
    </section>
  </main>
</body>
</html>`))

func (h *ConsentHandler) writeError(c *gin.Context, err error, returnTo string) {
	switch {
	case errors.Is(err, appconsent.ErrLoginRequired):
		redirectTo := withReturnTo("/login", c.Request.URL.RequestURI())
		c.Redirect(http.StatusFound, redirectTo)
	case errors.Is(err, appconsent.ErrInvalidReturnTo),
		errors.Is(err, appconsent.ErrInvalidClient),
		errors.Is(err, appconsent.ErrInvalidScope),
		errors.Is(err, appconsent.ErrInvalidAction):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "return_to": returnTo})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "consent processing failed"})
	}
}
