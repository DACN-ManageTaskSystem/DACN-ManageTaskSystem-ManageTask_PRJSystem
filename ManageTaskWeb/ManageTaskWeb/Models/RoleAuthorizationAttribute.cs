using System;
using System.Web.Mvc;
using System.Web;

public class RoleAuthorizationAttribute : AuthorizeAttribute
{
    private readonly string[] _allowedRoles;

    public RoleAuthorizationAttribute(params string[] roles)
    {
        _allowedRoles = roles;
    }

    protected override bool AuthorizeCore(HttpContextBase httpContext)
    {
        var userRole = httpContext.Session["Role"]?.ToString();
        if (string.IsNullOrEmpty(userRole))
            return false;

        return Array.Exists(_allowedRoles, role => role.Equals(userRole, StringComparison.OrdinalIgnoreCase));
    }

    protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
    {
        filterContext.Result = new RedirectResult("/Home/Unauthorized");
    }
}