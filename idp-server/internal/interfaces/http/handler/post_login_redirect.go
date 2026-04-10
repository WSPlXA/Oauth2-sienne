package handler

import (
	"strings"

	pkgrbac "idp-server/pkg/rbac"
)

func resolveBrowserPostLoginRedirect(returnTo, upstreamRedirectURI, roleCode string) string {
	if target := strings.TrimSpace(returnTo); target != "" {
		return target
	}
	if target := strings.TrimSpace(upstreamRedirectURI); target != "" {
		return target
	}
	switch strings.ToLower(strings.TrimSpace(roleCode)) {
	case pkgrbac.RoleSupport:
		return "/admin/workbench/support"
	case pkgrbac.RoleOAuthAdmin:
		return "/admin/workbench/oauth"
	case pkgrbac.RoleSecurityAdmin:
		return "/admin/workbench/security"
	case pkgrbac.RoleSuperAdmin:
		return "/admin"
	default:
		return ""
	}
}
