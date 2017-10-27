// Package google implements logging in through OpenID Connect providers.
package google

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/dex/connector"
	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
	"io/ioutil"
	"net/http"
	"strings"
)

// Config holds configuration options for OpenID Connect logins.
type Config struct {
	ClientID     string   `json:"clientID"`
	ClientSecret string   `json:"clientSecret"`
	RedirectURI  string   `json:"redirectURI"`
	// Optional whitelisted domain. If this field is nonempty,
	// only users from a this domain will be allowed to log in
	HostedDomain           string `json:"hostedDomain"`
	ServiceAccountJsonPath string `json:"serviceAccountJsonPath"`
	Subject                string `json:"subject"`
	GroupPrefix            string `json:"groupPrefix"`
}

func (c *Config) initDirectoryClient(serviceAccountJsonPath string, subject string) (*admin.Service, error) {
	serviceAccountJson, err := ioutil.ReadFile(serviceAccountJsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load service account json: %v", err)
	}
	b := []byte(serviceAccountJson)
	config, err := google.JWTConfigFromJSON(b,
		admin.AdminDirectoryGroupReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse client secret file to config: %v", err)
	}
	config.Subject = subject
	client, err := admin.New(config.Client(context.Background()))
	if err != nil {
		return nil, fmt.Errorf("failed to create directory service client: %v", err)
	}
	return client, nil
}

// Open returns a connector which can be used to login users through an upstream
// OpenID Connect provider.
func (c *Config) Open(logger logrus.FieldLogger) (conn connector.Connector, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	clientID := c.ClientID

	directoryClient, err := c.initDirectoryClient(c.ServiceAccountJsonPath, c.Subject)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("unable to initialize admin directory api client: %v", err)
	}

	return &googleConnector{
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{ClientID: clientID},
		),
		logger:          logger,
		cancel:          cancel,
		hostedDomain:    strings.TrimSpace(c.HostedDomain),
		directoryClient: directoryClient,
		groupPrefix:     c.GroupPrefix,
	}, nil
}

var (
	_ connector.CallbackConnector = (*googleConnector)(nil)
	_ connector.RefreshConnector  = (*googleConnector)(nil)
)

type googleConnector struct {
	redirectURI     string
	oauth2Config    *oauth2.Config
	verifier        *oidc.IDTokenVerifier
	ctx             context.Context
	cancel          context.CancelFunc
	logger          logrus.FieldLogger
	hostedDomain    string
	groupPrefix     string
	directoryClient *admin.Service
}

func (c *googleConnector) Close() error {
	c.cancel()
	return nil
}

func (c *googleConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}
	if len(c.hostedDomain) > 0 {
		return c.oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("hd", c.hostedDomain)), nil
	}
	return c.oauth2Config.AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *googleConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get token: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("oidc: no id_token in token response")
	}

	idToken, err := c.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to verify ID Token: %v", err)
	}

	var claims struct {
		Username      string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
	}

	if len(c.hostedDomain) > 0 {
		if claims.HostedDomain != c.hostedDomain {
			return identity, fmt.Errorf("oidc: unexpected hd claim %v", claims.HostedDomain)
		}
	}
	identity = connector.Identity{
		UserID:        idToken.Subject,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
	}

	return c.updateGroups(identity, s)
}

func (c *googleConnector) updateGroups(identity connector.Identity, s connector.Scopes) (connector.Identity, error){
	if s.Groups {
		groups, _ := c.getGroups(identity.Email)
		if len(groups) == 0 {
			return identity, fmt.Errorf("oidc: no groups for user %v", identity.Email)
		}
		identity.Groups = groups
	}
	return identity, nil
}

// getGroups retrieves groups starts with the prefix groupPrefix
func (c *googleConnector) getGroups(userLogin string) (groups []string, err error) {
	user_groups, err := c.directoryClient.Groups.List().Domain(c.hostedDomain).UserKey(userLogin).Do()
	if err != nil {
		return groups, fmt.Errorf("Unable to retrieve groups for customer %v", err)
	}
	if len(user_groups.Groups) == 0 {
		return groups, fmt.Errorf("No groups found %v", err)
	} else {
		for _, u := range user_groups.Groups {
			if strings.HasPrefix(u.Name, c.groupPrefix) {
				groups = append(groups, u.Name)
			}
		}
	}
	return groups, nil
}

// Refresh simply updates the group information
func (c *googleConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	return c.updateGroups(identity, s)
}
