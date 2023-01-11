
namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// This class contains extension methods related to the <see cref="WebApplicationBuilder"/>
/// type.
/// </summary>
public static class WebApplicationBuilderExtensions001
{
    // *******************************************************************
    // Public methods.
    // *******************************************************************

    #region Public methods

    /// <summary>
    /// This method registers the most common authentication and authorization
    /// services required for a typical server-side Blazor application.
    /// </summary>
    /// <param name="webApplicationBuilder">The web application builder to 
    /// use for the operation.</param>
    /// <param name="sectionName">The configuration section name to use
    /// for the operation.</param>
    /// <param name="bootstrapLogger">The optional bootstrap logger to use 
    /// for the operation.</param>
    /// <returns>The value of the <paramref name="webApplicationBuilder"/>
    /// parameter, for chaining calls together, Fluent style</returns>
    public static WebApplicationBuilder AddServerSideIdentity(
        this WebApplicationBuilder webApplicationBuilder,
        string sectionName = "Identity",
        ILogger? bootstrapLogger = null
        )
    {
        // Validate the arguments before attempting to use them.
        Guard.Instance().ThrowIfNull(webApplicationBuilder, nameof(webApplicationBuilder))
            .ThrowIfNullOrEmpty(sectionName, nameof(sectionName));

        // Tell the world what we are about to do.
        bootstrapLogger?.LogDebug(
            "Configuring identity options from the {section} section",
            sectionName
            );

        // Configure the identity options.
        webApplicationBuilder.Services.ConfigureOptions<IdentityOptions>(
            webApplicationBuilder.Configuration.GetSection(sectionName),
            out var identityOptions
            );

        // Authentication related services will crash if any of the configuration
        //   settings are missing, at this point. They can be missing if the 
        //   DeveloperBypass flag is true (that's the whole point of the flag).
        // So, we'll need to make sure we don't try to register authentication
        //   services if the bypass flag is true.

        // Should we bypass identity?
        if (identityOptions.DeveloperBypass)
        {
            // Is this a development environment?
            if (webApplicationBuilder.Environment.IsDevelopment())
            {
                // If we get here then the system is running in a development 
                //   environment, and the DeveloperBypass flag is true, so 
                //   we'll bypass the authentication services.

                // Tell the world what we are about to do.
                bootstrapLogger?.LogWarning(
                    "Bypassing identity because the '{name}' flag is true.",
                    nameof(IdentityOptions.DeveloperBypass)
                    );
            }
            else
            {
                // If we get here then the system is NOT running in a development 
                //   environment, so we don't care about the DeveloperBypass flag,
                //   we're going to register authentication services normally.

                // Tell the world what we aren't doing.
                bootstrapLogger?.LogWarning(
                    "Not bypassing identity because the environment isn't 'Development'."
                    );

                // Tell the world what we are about to do.
                bootstrapLogger?.LogDebug(
                    "Adding authentication, cookies and JWT services, for identity."
                    );

                // Register the authentication services.
                webApplicationBuilder.AddAuthenticationServices(
                    identityOptions,
                    bootstrapLogger
                    );
            }
        }
        else
        {
            // If we get here then the DeveloperBypass flag is false, so we should
            //   register the authentication services normally.

            // Tell the world what we are about to do.
            bootstrapLogger?.LogDebug(
                "Adding authentication, cookies and JWT services, for identity."
                );

            // Register the authentication services.
            webApplicationBuilder.AddAuthenticationServices(
                    identityOptions,
                    bootstrapLogger
                    );
        }

        // Tell the world what we are about to do.
        bootstrapLogger?.LogDebug(
            "Adding authorization services, for identity."
            );

        // Authorization services are a bit different than authentication,
        //   since we still need the policies in place - even if they don't
        //  actually do anything (like when the DeveloperBypass flag is true).

        // Wire up the authorization services.
        webApplicationBuilder.Services.AddAuthorization(options =>
        {
            // Add the 'standard policy' policy.
            options.AddPolicy(PolicyNameDefaults.StandardPolicy, policy =>
            {
                // Should we bypass all identity?
                if (identityOptions.DeveloperBypass)
                {
                    // Are we a development environment?
                    if (webApplicationBuilder.Environment.IsDevelopment())
                    {
                        // This policy allows anyone to access anything.
                        policy.RequireAssertion(x => true);
                    }
                    else
                    {
                        // This policy requires an authenticated user.
                        policy.RequireAuthenticatedUser();
                    }
                }
                else
                {
                    // This policy requires an authenticated user.
                    policy.RequireAuthenticatedUser();
                }
            });

            // Add the 'super admin' policy.
            options.AddPolicy(PolicyNameDefaults.SuperAdminPolicy, policy =>
            {
                // Should we bypass all identity?
                if (identityOptions.DeveloperBypass)
                {
                    // Are we a development environment?
                    if (webApplicationBuilder.Environment.IsDevelopment())
                    {
                        // This policy allows anyone to access anything.
                        policy.RequireAssertion(x => true);
                    }
                    else
                    {
                        // This policy requires these roles.
                        policy.RequireRole(RoleNameDefaults.SuperAdmin);
                    }
                }
                else
                {
                    // By default this policy only allows these roles.
                    policy.RequireRole(RoleNameDefaults.SuperAdmin);
                }
            });

            // Add the 'admin' policy.
            options.AddPolicy(PolicyNameDefaults.AdminPolicy, policy =>
            {
                // Should we bypass all identity?
                if (identityOptions.DeveloperBypass)
                {
                    // Are we a development environment?
                    if (webApplicationBuilder.Environment.IsDevelopment())
                    {
                        // This policy allows anyone to access anything.
                        policy.RequireAssertion(x => true);
                    }
                    else
                    {
                        // This policy requires these roles.
                        policy.RequireRole(RoleNameDefaults.Admin);
                    }
                }
                else
                {
                    // By default this policy only allows these roles.
                    policy.RequireRole(RoleNameDefaults.Admin);
                }
            });
        });

        // Is this a development environment?
        if (webApplicationBuilder.Environment.IsDevelopment())
        {
            // Tell the world what we are about to do.
            bootstrapLogger?.LogDebug(
                "Enabling PII, for identity, because this is a development environment"
                );

            // Tell IdentityServer to include PII.
            IdentityModelEventSource.ShowPII = true;
        }

        // Return the application builder.
        return webApplicationBuilder;
    }

    #endregion

    // *******************************************************************
    // Private methods.
    // *******************************************************************

    #region Private methods

    private static WebApplicationBuilder AddAuthenticationServices(
        this WebApplicationBuilder webApplicationBuilder,
        IdentityOptions identityOptions,
        ILogger? bootstrapLogger = null
        )
    {
        // Tell the world what we are about to do.
        bootstrapLogger?.LogDebug(
            "Clearing default inbound claims mapping, for identity."
            );

        // Clear default inbound claim mapping.
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        // Wire up the authentication, cookie, OIDC and JWT services.
        webApplicationBuilder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.Cookie.Name = identityOptions.CookieName;
            options.Cookie.SameSite = SameSiteMode.None;
        }).AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            // Where our identity server is.
            options.Authority = identityOptions.Authority;

            // Are we in a development environment?
            if (webApplicationBuilder.Environment.IsDevelopment())
            {
                // Don't require HTTPS for meta-data
                options.RequireHttpsMetadata = false;
            }

            // This is who we are.
            options.ClientId = identityOptions.ClientId;

            // This is what we know.
            options.ClientSecret = identityOptions.ClientSecret;

            // We want an authentication code response.
            options.ResponseType = "code";

            options.ResponseMode = "query";

            // Don't map claims.
            options.MapInboundClaims = false;

            // Access and Refresh token stored in the authentication properties.
            options.SaveTokens = true;

            // Go to the user info endpoint for additional claims.
            options.GetClaimsFromUserInfoEndpoint = true;

            // We want these scopes, by default.
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");

            // Loop and add any additional scopes.
            foreach (var scope in identityOptions.AdditionalScopes)
            {
                // Ignore these, since we've already added them.
                if (string.Compare(scope, "openid", true) == 0 ||
                    string.Compare(scope, "profile", true) == 0)
                {
                    continue;
                }

                // Add the scope.
                options.Scope.Add(scope);
            }

            // Map role claim(s) so ASP.NET will understand them.
            options.ClaimActions.MapJsonKey("role", "role", "role");

            // Require these types for a valid token.
            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = "role"
            };

            // Tap into the ODIC events.
            options.Events = new OpenIdConnectEvents
            {
                // On access denied, we want to go back to our home page.
                OnAccessDenied = context =>
                {
                    context.HandleResponse();
                    context.Response.Redirect("/");
                    return Task.CompletedTask;
                }
            };
        }).AddJwtBearer(options =>
        {
            options.Authority = identityOptions.Authority;
            options.TokenValidationParameters.ValidateAudience = false;
        });

        // Return the application builder.
        return webApplicationBuilder;
    }

    #endregion
}
