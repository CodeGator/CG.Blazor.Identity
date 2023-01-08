
namespace CG.Blazor.Identity.Options;

/// <summary>
/// This class contains configuration settings for identity operations.
/// </summary>
public class IdentityOptions
{
    // *******************************************************************
    // Properties.
    // *******************************************************************

    #region Properties

    /// <summary>
    /// This property indicates when a developer bypass is in effect, which 
    /// allows quick access to everything without requiring credentials of 
    /// any kind (only works in a development environment).
    /// </summary>
    public bool DeveloperBypass { get; set; }

    /// <summary>
    /// This property contains the URL for the identity authority.
    /// </summary>
    [Required]
    public string Authority { get; set; } = null!;

    /// <summary>
    /// This property contains the client identifier.
    /// </summary>
    [Required]
    public string ClientId { get; set; } = null!;

    /// <summary>
    /// This property contains the client secret.
    /// </summary>
    [Required]
    public string ClientSecret { get; set; } = null!;

    /// <summary>
    /// This property contains the cookie name.
    /// </summary>
    [Required]
    public string CookieName { get; set; } = "__AuthCookie";

    /// <summary>
    /// This property contains a list of additional scopes that should be
    /// required for identity purposes ('openid' and 'profile' are always 
    /// required, no matter what).
    /// </summary>
    public List<string> AdditionalScopes { get; set; } = new();

    #endregion
}
