
namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// This class contains extension methods related to the <see cref="WebApplication"/>
/// type.
/// </summary>
public static class WebApplicationExtensions001
{
    // *******************************************************************
    // Public methods.
    // *******************************************************************

    #region Public methods

    /// <summary>
    /// This method registers middleware required for a typical server-side 
    /// Blazor application.
    /// </summary>
    /// <param name="webApplication">The web application to use for the 
    /// operation.</param>
    /// <returns>The value of the <paramref name="webApplication"/>
    /// parameter, for chaining calls together, Fluent style</returns>
    public static WebApplication UseServerSideIdentity(
        this WebApplication webApplication
        )
    {
        // Validate the arguments before attempting to use them.
        Guard.Instance().ThrowIfNull(webApplication, nameof(webApplication));

        // Log what we are about to do.
        webApplication.Logger.LogDebug(
            "Wiring up the cookie policy, for identity."
            );

        // Use out cookie policy.
        webApplication.UseCookiePolicy();

        // Log what we are about to do.
        webApplication.Logger.LogDebug(
            "Wiring up middleware, for identity."
            );

        // Use the authorization middleware.
        webApplication.UseAuthorization();

        // Use the authentication middleware.
        webApplication.UseAuthentication();

        // Return the results.
        return webApplication;
    }

    #endregion
}
