
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CG.Blazor.Identity.QuickStart.Pages.Account;

/// <summary>
/// This class is the code-behind for the Login page.
/// </summary>
public class LoginModel : PageModel
{
    // *******************************************************************
    // Public methods.
    // *******************************************************************

    #region Public methods

    /// <summary>
    /// This method is called when the get receives a GET request.
    /// </summary>
    /// <param name="redirectUri">The redirect uri to use for the operation.</param>
    /// <returns>A task to perform the operation.</returns>
    public async Task OnGet(string redirectUri)
    {
        await HttpContext.ChallengeAsync(
            OpenIdConnectDefaults.AuthenticationScheme, 
            new AuthenticationProperties { RedirectUri = redirectUri ?? "/" }
            );
    }

    #endregion
}
