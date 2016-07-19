package connector

import (
	"html/template"
	"net/http"
	"net/url"
	"path"

	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
)

const (
	AzureConnectorType = "azure"
)

func init() {
	RegisterConnectorConfigType(AzureConnectorType, func() ConnectorConfig { return &AzureConnectorConfig{} })
}

type AzureConnectorConfig struct {
	OIDCConnectorConfig
}

func (cfg *AzureConnectorConfig) ConnectorType() string {
	return AzureConnectorType
}

type AzureConnector struct {
	OIDCConnector
}

func (cfg *AzureConnectorConfig) Connector(ns url.URL, lf oidc.LoginFunc, tpls *template.Template) (Connector, error) {
	ns.Path = path.Join(ns.Path, httpPathCallback)

	ccfg := oidc.ClientConfig{
		RedirectURL: ns.String(),
		Credentials: oidc.ClientCredentials{
			ID:     cfg.ClientID,
			Secret: cfg.ClientSecret,
		},
	}

	cl, err := oidc.NewClient(ccfg)
	if err != nil {
		return nil, err
	}

	idpc := &AzureConnector{
		OIDCConnector{
			id:                   cfg.ID,
			issuerURL:            cfg.IssuerURL,
			cbURL:                ns,
			loginFunc:            lf,
			client:               cl,
			trustedEmailProvider: cfg.TrustedEmailProvider,
		},
	}
	return idpc, nil
}

func (c *AzureConnector) Register(mux *http.ServeMux, errorURL url.URL) {
	mux.Handle(c.cbURL.Path, c.handleCallbackFunc(c.loginFunc, errorURL))
}

func (c *AzureConnector) handleCallbackFunc(lf oidc.LoginFunc, errorURL url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		e := q.Get("error")
		if e != "" {
			redirectError(w, errorURL, q)
			return
		}

		code := q.Get("code")
		if code == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "code query param must be set")
			redirectError(w, errorURL, q)
			return
		}

		tok, err := c.client.ExchangeAuthCode(code)
		if err != nil {
			log.Errorf("Unable to verify auth code with issuer: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to verify auth code with issuer")
			redirectError(w, errorURL, q)
			return
		}

		claims, err := tok.Claims()
		if err != nil {
			log.Errorf("Unable to construct claims: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to construct claims")
			redirectError(w, errorURL, q)
			return
		}

		// ID Token issued by Azure AD does not contain a email claim.
		// So we need to copy the value from upn claim to email claim.
		upn, ok, err := claims.StringClaim("upn")
		if err != nil || !ok {
			log.Errorf("Failed parsing upn claim from remote provider: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to get the value of upn claim")
			redirectError(w, errorURL, q)
			return
		}
		claims.Add("email", upn)

		ident, err := oidc.IdentityFromClaims(claims)
		if err != nil {
			log.Errorf("Failed parsing claims from remote provider: %v", err)
			q.Set("error", oauth2.ErrorUnsupportedResponseType)
			q.Set("error_description", "unable to convert claims to identity")
			redirectError(w, errorURL, q)
			return
		}

		sessionKey := q.Get("state")
		if sessionKey == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "missing state query param")
			redirectError(w, errorURL, q)
			return
		}

		redirectURL, err := lf(*ident, sessionKey)
		if err != nil {
			log.Errorf("Unable to log in %#v: %v", *ident, err)
			q.Set("error", oauth2.ErrorAccessDenied)
			q.Set("error_description", "login failed")
			redirectError(w, errorURL, q)
			return
		}

		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusFound)
		return
	}
}
