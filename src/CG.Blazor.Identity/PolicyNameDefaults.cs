
namespace CG.Blazor.Identity;

/// <summary>
/// This class utility contains constants related to identity policies.
/// </summary>
public static class PolicyNameDefaults
{
    // *******************************************************************
    // Constants.
    // *******************************************************************

    #region Constants

    /// <summary>
    /// This constant contains the name of a policy that requires a 'SuperAdmin'
    /// role, for authorization purposes.
    /// </summary>
    public const string SuperAdminPolicy = "SuperAdminPolicy";

    /// <summary>
    /// This constant contains the name of a policy that requires an 'Admin'
    /// role, for authorization purposes.
    /// </summary>
    public const string AdminPolicy = "AdminPolicy";

    /// <summary>
    /// This constant contains the name of a policy that requires an 
    /// authenticated user, for authorization purposes.
    /// </summary>
    public const string StandardPolicy = "StandardPolicy";

    #endregion
}
