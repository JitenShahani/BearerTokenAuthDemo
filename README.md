# Identity based Bearer Token Auth Demo

A Web API built using ASP.NET Core, demonstrating secure authentication and role-based authorization using Identity-based Bearer tokens. Unlike custom JWT implementations or external OAuth flows, this demo leverages ASP.NET Core Identity with `AddBearerToken()`. A built-in feature introduced in .NET 8 that simplifies token management. It automatically handles access and refresh token lifecycles, integrates with Identity roles and claims, and offers secure storage and revocation patterns out-of-the-box.

🛡️ As developers, we are responsible for managing the Identity store (users, roles, tokens, claim, etc...) within our application database. This means authentication is entirely self-contained offering flexibility and full control, but also placing the burden of securing credentials, enforcing policies, and protecting sensitive data directly on the developer and infrastructure.

The project combines this with minimal APIs and follows modern .NET practices for clarity, scalability, and security.

## 🔧 Technologies Used

- ASP.NET Core (.NET 10)
- ASP.NET Core Identity
- Entity Framework Core with SQLite
- Minimal APIs
- Role-based Authorization
- OpenAPI with Scalar UI integration

## 📂 Project Structure Overview

```
BearerTokenAuthDemo/
	├── Data/
	│   └── AppDbContext.cs					# EF Core DbContext with Identity
	├── DTO/
	│   └── Shirt.cs						# DTO for form-data binding
	│   └── WeatherForecast.cs				# DTO for weather forecast response
	├── Endpoints.cs						# Minimal API endpoints and route groups
	├── GlobalUsings.cs						# Global using directives
	├── IdentityDemo.db						# SQLite database file (Identity)
	├── Program.cs							# Main entry point, DI, and app setup
	├── Requests.http						# HTTP request samples for testing endpoints
	├── RolesAndUserConfig.cs				# Seeding logic
```

## ⚠️ Development-Only Configuration Warnings

```
This project includes diagnostics and logging settings tailored for development environments only.
These must be carefully reviewed and adjusted before deploying to production.
```

### 🔍 Summary of Risky Configurations

| Configuration							| Purpose										| Production Risk												|
|---------------------------------------|-----------------------------------------------|---------------------------------------------------------------|
| `EnableDetailedErrors()`				| Enables verbose EF Core errors				| May leak internal stack traces or SQL behavior				|
| `EnableSensitiveDataLogging()`		| Logs SQL with parameters and context			| Can expose sensitive info (PII, tokens)						|
| `RequireAuthenticatedUser()` (global)	| Auth required for all endpoints by default	| Restricts public access unless explicitly allowed				|
| `.AddFilter("Auth...", ...)`			| Targets auth logs only						| May suppress unrelated logs unless explicitly reconfigured	|

## 🔧 Configuration Blocks Explained

### 🗄️ AppDbContext Configuration

This project uses AppDbContext as the EF Core store for Identity and related tables.

```csharp
public class AppDbContext : IdentityDbContext<IdentityUser>
{
	public AppDbContext (DbContextOptions options) : base (options) { }
}
```

ℹ️ **Note**: The AppDbContext inherits from `IdentityDbContext<IdentityUser>`, enabling built-in support for Identity-related entities such as users, roles, tokens, claims, and logins. This integration ensures that tables are scaffolded automatically via EF Core migrations and aligns with the behavior of ASP.NET Core Identity APIs.

#### 🧠 Built-In Identity Types Explained

These types are provided by the `Microsoft.AspNetCore.Identity` namespace and form the backbone of the Identity system in ASP.NET Core. They enable authentication, role management, and token workflows with minimal configuration:

- `IdentityUser`
  Represents a user account in the Identity system. It includes fields like `UserName`, `Email`, `PasswordHash`, `SecurityStamp`, and navigation properties for claims, logins, tokens, and roles. You can extend it with custom properties like `DisplayName`, `ProfilePicture`, or `DepartmentId` by creating a subclass, e.g., `AppUser : IdentityUser`.

- `IdentityRole`
  Defines a named role (`Admin`, `User`, etc.) that can be assigned to users for role-based authorization. Each role is persisted with an Id and Name, and supports claims to enforce granular policies. It supports claims and policies, allowing you to restrict route access using `[Authorize(Roles = "Admin")]`.

- `IdentityConstants`
  A static class that houses standard constants used across Identity such as token schemes (`BearerScheme`, `ApplicationScheme`) and cookie names. Using these ensures compatibility with middleware and `AddBearerToken()` configuration. For example, `IdentityConstants.BearerScheme` is required when setting up `AddBearerToken()` so authentication works with ASP.NET Core’s pipeline.

These built-in types are deeply integrated into ASP.NET Core's Identity infrastructure and are automatically handled when using `AddIdentityCore()`, `AddRoles()`, and `AddEntityFrameworkStores()` in your DI configuration.

### 🪵 Logging & EF Core Setup

```csharp
builder.Logging
    .AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug)
    .AddFilter("Microsoft.AspNetCore.Authorization", LogLevel.Debug);

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.EnableDetailedErrors();
    options.EnableSensitiveDataLogging();
});
```

Logs detailed authentication & authorization flows and enables EF Core diagnostics.

> ⚠️ This EF Core setup is tailored for debugging in development environments.
> Avoid using these options in production. Refer to [⚠️ Development-Only Configuration Warnings](#development-only-configuration-warnings) for details.

### 🔐 Identity & BearerToken Settings

```csharp
// Configure Identity Services
builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        // User Settings
        // Restricts allowable username characters and enforces unique email per user
        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        options.User.RequireUniqueEmail = true;

        // Password Settings
        // Enforces strong password policy for better security hygiene
        options.Password.RequireDigit = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;

        // Lockout Settings
        // Automatically locks out users on repeated failed login attempts
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

        // SignIn Settings
        // Requires users to verify their email before login is allowed
        options.SignIn.RequireConfirmedEmail = true;
    })
    // Enables Role-based access control via ASP.NET Core Identity
    .AddRoles<IdentityRole>()
    // Configures EF Core to use AppDbContext as Identity store
    .AddEntityFrameworkStores<AppDbContext>()
    // Adds built-in Identity API endpoints (login, register, etc.)
    .AddApiEndpoints();

// Configure Authentication
builder.Services
	.AddAuthentication ()
	.AddBearerToken (IdentityConstants.BearerScheme, options =>
	{
		// Set token expiration to 1 hour - Default Value
		options.BearerTokenExpiration = TimeSpan.FromSeconds (3600);

		// Set Refresh token expiration to 2 hours
		options.RefreshTokenExpiration = TimeSpan.FromSeconds (7200);
	});
```

Configures Identity for authentication and role management. Bearer token lifetime and refresh durations are explicitly set.

### 📘 Configuring OpenAPI

This section sets up ASP.NET Core's built-in OpenAPI generator to produce structured documentation for all annotated endpoints. It includes custom metadata, tag organization, and security schemes compatible with Scalar UI.

```csharp
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer(async (document, context, cancellationToken) =>
    {
        // Provide title, description, contact, and license details
        document.Info.Version = "v1";
        document.Info.Title = "Bearer Token Identity Demo";
        document.Info.Description = "A sample application to demonstrate Bearer Token authentication and authorization in Minimal APIs.";
        document.Info.Contact = new OpenApiContact
        {
            Name = "Jiten Shahani",
            Email = "shahani.jiten@gmail.com",
            Url = new Uri("https://github.com/JitenShahani")
        };
        document.Info.License = new OpenApiLicense
        {
            Name = "MIT License",
            Url = new Uri("https://opensource.org/license/mit")
        };

        // Group endpoints by tags for UI clarity
        document.Tags = [
            new OpenApiTag
            {
                Name = "Auth",
                Description = "Endpoints for user registration, login, and account management using ASP.NET Core Identity.",
                ExternalDocs = new OpenApiExternalDocs
                {
                    Description = "Bearer Token Authentication in ASP.NET Core",
                    Url = new Uri("https://devblogs.microsoft.com/dotnet/bearer-token-authentication-in-asp-net-core/")
                }
            },
            new OpenApiTag
            {
                Name = "Home",
                Description = "Endpoints for general API information, welcome messages, and endpoints that may or may not require authentication."
            },
            new OpenApiTag
            {
                Name = "Weather",
                Description = "Endpoints providing weather forecast data."
            },
            new OpenApiTag
            {
                Name = "Greeting",
                Description = "Endpoint for greeting users based on the input value."
            }
        ];

        // Inject Bearer Token security scheme for protected endpoints
        var schemeProvider = context.ApplicationServices.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = await schemeProvider.GetAllSchemesAsync();

        if (schemes.Any(s => s.Name == IdentityConstants.BearerScheme))
        {
            document.Components ??= new OpenApiComponents();

            document.Components.SecuritySchemes = new Dictionary<string, IOpenApiSecurityScheme>
            {
                [IdentityConstants.BearerScheme] = new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    In = ParameterLocation.Header,
                    Description = "Identity Bearer Token. Paste the Bearer token below.",
                    BearerFormat = "Opaque"	// ✅ Correct format for Identity tokens
                }
            };

            document.Security = [
                new OpenApiSecurityRequirement
                {
                    [new OpenApiSecuritySchemeReference("bearer", document, null)] = []
                }
            ];
        }
    });
});
```
### 🔐 Configuring Authentication
Authentication is powered by ASP.NET Core Identity with Bearer tokens. The following configuration sets up token generation and expiration using the default scheme.

```csharp
builder.Services
	.AddAuthentication()
	.AddBearerToken(IdentityConstants.BearerScheme, options =>
	{
		// Set token expiration to 1 hour - Default Value
		options.BearerTokenExpiration = TimeSpan.FromSeconds(3600);

		// Set Refresh token expiration to 2 hours
		options.RefreshTokenExpiration = TimeSpan.FromSeconds(7200);
	});
```

This ensures that authenticated users receive secure Bearer tokens with refresh capabilities. These are automatically validated by the middleware and injected into protected endpoints.

Authentication middleware is activated in the request pipeline:

```csharp
app.UseAuthentication();
```

### 🛡️ Configuring Authorization

Authorization is globally enforced using a fallback policy. All endpoints require authentication unless explicitly marked. This setup ensures consistent enforcement of identity and role checks across your API surface. Protected endpoints validate Bearer tokens automatically.

```csharp
builder.Services.AddAuthorization(options =>
{
	options.DefaultPolicy = new AuthorizationPolicyBuilder()
		.RequireAuthenticatedUser()
		.AddAuthenticationSchemes(IdentityConstants.BearerScheme)
		.Build();

	options.FallbackPolicy = options.DefaultPolicy;
});
```

ℹ️ **Remember**: Public access must be explicitly declared:

- Use `.AllowAnonymous()` on minimal API endpoints.
- Use `[AllowAnonymous]` attribute on controllers or controller based actions.

Authorization middleware is activated via:

```csharp
app.UseAuthorization();
```

🛑 **Production Note**: While `RequireAuthenticatedUser()` globally ensures a secure API by default, this approach may be too restrictive for production apps that require fine-grained access control. In such cases, it’s often better to:

- Apply `[Authorize]` on controllers or controller actions or use `.RequireAuthorization()` on minimal API endpoints to enforce authentication.
- Use named policies for role or claim-based access.
- Set `FallbackPolicy` to `null` or define role-specific policies as needed if global enforcement isn’t appropriate.

This setup is ideal for internal APIs or secured development environments but should be revisited when exposing public-facing endpoints.

### 📲 Endpoint Summary

| Route									| Method | Access		 | Group	| Description										|
|---------------------------------------|--------|---------------|----------|---------------------------------------------------|
| /authRequired							| GET	 | Authenticated | Home		| Returns user info via `ClaimsPrincipal`.			|
| /getToken								| GET	 | Authenticated | Home		| Retrieves Bearer token from headers.				|
| /admin								| GET	 | Role: Admin   | Home		| Secured via role-based authorization.				|
| /noAuthRequired						| GET	 | Public        | Home		| Anonymous greeting.								|
| /form-input							| POST	 | Authenticated | Home		| Accepts form data for Shirt record.				|
| /greet								| GET	 | Authenticated | Greeting	| Greet user via query param.						|
| /weatherForecast						| GET	 | Authenticated | —		| Returns mock weather data.						|
| /api/Account/register					| POST	 | Public        | Auth		| Registers a new user account.						|
| /api/Account/login					| POST	 | Public        | Auth		| Logs in the user and returns a Bearer token.		|
| /api/Account/refresh					| POST	 | Authenticated | Auth		| Refreshes the access token using refresh token.	|
| /api/Account/confirmEmail				| GET	 | Public        | Auth		| Verifies user's email address.					|
| /api/Account/resendConfirmationEmail	| POST	 | Public        | Auth		| Resends confirmation email to the user.			|
| /api/Account/forgotPassword			| POST	 | Public        | Auth		| Initiates password reset workflow.				|
| /api/Account/resetPassword			| POST	 | Public        | Auth		| Applies new password using reset token.			|
| /api/Account/manage/2fa				| POST	 | Authenticated | Auth		| Enables or disables two-factor authentication.	|
| /api/Account/manage/info				| GET	 | Authenticated | Auth		| Retrieves profile details for logged-in user.		|
| /api/Account/manage/info				| POST	 | Authenticated | Auth		| Updates profile details for logged-in user.		|

ℹ️ **Remember**: Token refresh is handled via `/api/Account/refresh` (built into `MapIdentityApi`). Clients should call this endpoint using their refresh token before the access token expires.

#### 🔐 MapIdentityApi — Built-In Auth Endpoint Registration

📌 Auth based endpoints are automatically exposed through `MapIdentityApi<IdentityUser>()`, and are tagged with "Auth" for Scalar UI grouping. These endpoints support built-in Identity workflows and align with token issuance, user management, and 2FA features included in ASP.NET Core Identity.

```csharp
app
    .MapGroup("/api/Account")				// Groups identity endpoints under a common prefix
    .MapIdentityApi<IdentityUser>()			// Registers built-in Identity endpoints
    .WithOpenApi()							// Includes in OpenAPI spec
    .WithTags("Auth")						// Visible under the "Auth" group in Scalar UI
    .WithDescription("Endpoints for managing user accounts, including registration, login, and profile management.")
    .AllowAnonymous();						// Allows public access to initial auth endpoints
```

🧠 **Purpose**: This single mapping exposes the full suite of Identity-based authentication and account management APIs automatically. These endpoints support secure workflows out of the box and integrate seamlessly with Bearer token validation. They're tagged "Auth" for OpenAPI clarity and discoverability in Scalar UI.

🔧 These endpoints are available because `AddApiEndpoints()` was included in the Identity service configuration.

#### 🗂️ Grouped Endpoints using `RouteGroupBuilder`

This project organizes endpoints into **tagged route groups** using `RouteGroupBuilder`, which enhances clarity, access control, and OpenAPI documentation.

##### 🏠 `homeGroup`

```csharp
var homeGroup = app.MapGroup ("/")
	.WithOpenApi ()
	.WithTags ("Home")
	.RequireAuthorization();
```

- Handles general-purpose endpoints.
- Includes:
	- /authRequired
	- /getToken
	- /admin
	- /form-input
	- /noAuthRequired
- Tag: "Home" for OpenAPI grouping to organize these in Scalar UI.

##### 🙋‍♂️ `greetGroup`

```csharp
var greetGroup = app.MapGroup ("/greet")
	.WithOpenApi ()
	.WithTags ("Greeting")
	.RequireAuthorization ();
```

- Focused on user-specific greetings.
- Includes:
	- /greet
- Tag: "Greeting" for OpenAPI grouping to organize these in Scalar UI.

##### 🌤️ `/weatherForecast` route

```csharp
app.MapGet("/weatherForecast", () => ...)
    .WithOpenApi()
    .WithName("GetWeatherForecast")
    .WithTags("Weather")
	...
```

- Not part of a route group. Defined directly on app.MapGet.
- Tag: "Weather" for OpenAPI grouping to organize these in Scalar UI.

This setup allows you to:

- Enforce authorization per group.
- Fine-tune endpoint tags for OpenAPI visual navigation.

ℹ️ **Note**: Tags assigned via `.WithTags("...")` determine how endpoints appear in Scalar UI independent of the route group name. The route group itself handles path prefixing and shared policies.

#### 🧭 Endpoints Explained

##### `/authRequired`
- **Method**: `GET`
- **Access**: Authenticated
- **Parameters**: None

```csharp
homeGroup.MapGet ("/authRequired", (ClaimsPrincipal user) =>
{
	List<string> roles = [];

	if (user!.Identity!.IsAuthenticated)
		roles = [.. user.FindAll (ClaimTypes.Role).Select (r => r.Value)];

	var result = new
	{
		Message = $"Welcome to the Bearer Token Identity Demo API! You are logged in as {user.Identity?.Name}.",
		Roles = roles
	};

	return TypedResults.Ok (result);
})
	.WithSummary ("Auth Required")
	.WithDescription ("A simple root endpoint that returns a welcome message.")
	.Produces (StatusCodes.Status200OK)
	.Produces (StatusCodes.Status401Unauthorized);
```

🧠 **Purpose**: This endpoint verifies that the incoming request is authenticated and leverages ClaimsPrincipal to extract user identity and role claims.

It returns:

- The authenticated user's name.
- A list of all role claims assigned to that user.

This route is particularly helpful for:

- Testing role propagation and Identity-based token decoding.
- Inspecting the structure of ClaimsPrincipal during development.
- Validating whether policies and token payloads are resolved correctly at runtime.

---

##### `/getToken`
- **Method**: `GET`
- **Access**: Authenticated
- **Parameters**: None

```csharp
homeGroup.MapGet ("/getToken", (HttpContext httpContext) =>
{
	var requestToken =
		httpContext.Request.Headers["Authorization"].ToString ().Replace ("Bearer ", "");

	// You could also directly access the Authorization object/dictionary.
	// var requestToken = httpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");

	return TypedResults.Ok (new { authToken = requestToken });
})
	.WithSummary ("Get Authorization Token")
	.WithDescription ("Endpoint to retrieve an authentication token for the user.")
	.Produces (StatusCodes.Status200OK)
	.Produces (StatusCodes.Status401Unauthorized);
```

🧠 **Purpose**: This endpoint extracts and returns the Bearer token string from the incoming Authorization header. While the request must be authenticated due to the global policy, this route focuses solely on displaying the raw token sent by the client.

It returns:

- The token string passed by the client in the request header.

This route is particularly helpful for:

- Verifying that clients (e.g., Postman, Scalar UI) are correctly formatting `Authorization` headers.
- Debugging token propagation issues during development.
- Inspecting raw token values before decoding or middleware evaluation.

🚫 Not intended for production. Exposing tokens without context may lead to security risks.

---

##### `/admin`
- **Method**: `GET`
- **Access**: Role: `Admin`
- **Parameters**: None

```csharp
homeGroup.MapGet ("/admin", () => TypedResults.Ok (new { Message = "Welcome, Admin!" }))
	.WithSummary ("Admin Only")
	.WithDescription ("This endpoint is accessible only to users with the Admin role.")
	.RequireAuthorization (policy => policy.RequireRole ("Admin"))
	.Produces (StatusCodes.Status200OK)
	.Produces (StatusCodes.Status401Unauthorized)
	.Produces (StatusCodes.Status403Forbidden);
```

🧠 **Purpose**: This endpoint restricts access to users with the Admin role and demonstrates role-based authorization in minimal APIs.

It returns:

- A confirmation message for users who possess the required role.

This route is particularly helpful for:

- Validating role assignment and enforcement during authentication.
- Testing policy-based access controls tied to bearer tokens.
- Ensuring sensitive routes are protected by fine-grained authorization strategies.

🚫 A regular Bearer token without the "Admin" claim will trigger a 403 Forbidden confirming proper enforcement.

---

##### `/noAuthRequired`
- **Method**: `GET`
- **Access**: Public
- **Parameters**: None

```csharp
homeGroup.MapGet ("/noAuthRequired", () => TypedResults.Ok (new { Message = "Hello, from `Auth Not Required` endpoint..." }))
	.WithSummary ("Auth Not Required")
	.WithDescription ("Authentication is not required!")
	.AllowAnonymous ()
	.Produces (StatusCodes.Status200OK);
```

🧠 **Purpose**: This endpoint serves as a public access point that bypasses the global authentication requirement using `.AllowAnonymous()`. It demonstrates how to override default security policies for routes meant to be accessible without a Bearer token. For controllers or controller-based action methods, decorate with `[AllowAnonymous]` attribute.

It returns:

- A welcome message for unauthenticated users.

This route is particularly helpful for:

- Verifying that anonymous access is properly configured in a secured API.
- Serving health checks, landing pages, or API instructions without requiring login.
- Testing endpoint visibility without triggering authentication middleware.

---

##### `/greet`
- **Method**: `GET`
- **Access**: Authenticated
- **Parameters**: Query → `name`

```csharp
greetGroup.MapGet ("", (string? name) =>
{
	var message = string.IsNullOrWhiteSpace (name)
		? "Hello, Guest!"
		: $"Hello, {name}!";

	return TypedResults.Ok (new { Message = message });
})
	.WithSummary ("Greet a user")
	.WithDescription ("Returns a personalized greeting based on the provided query parameter.")
	.Produces (StatusCodes.Status200OK)
	.Produces (StatusCodes.Status401Unauthorized);
```

🧠 **Purpose**: This endpoint returns a personalized greeting based on the optional `name` query parameter. If no name is provided, it defaults to a generic message.

It returns:

- A greeting message tailored to the provided name or fallback text.

This route is particularly helpful for:

- Demonstrating query parameter binding with minimal APIs.
- Building dynamic responses based on user input.
- Exploring simple personalization patterns without requiring complex model binding.

---

##### `/form-input`
- **Method**: `POST`
- **Access**: Authenticated
- **Parameters**: Form → `Shirt` model
  - Fields: `ShirtId`, `Brand`, `Color`, `Size`, `Price`

```csharp
homeGroup.MapPost ("/form-input", ([FromForm] Shirt shirt) => TypedResults.Ok (shirt))
	.WithSummary ("Create a new Shirt using Form Data")
	.WithDescription ("This endpoint helps create a new shirt using the Form data.")
	.Produces (StatusCodes.Status200OK)
	.DisableAntiforgery ();
```

It returns:

- A `Shirt` object parsed from submitted form fields and echoed back to the client.

This route is particularly helpful for:

- Exploring how minimal APIs handle `multipart/form-data` POST requests.
- Testing form submissions in Postman, Insomnia, or Scalar UI.
- Demonstrating the use of `.DisableAntiforgery()` to bypass built-in antiforgery protections for API scenarios that don’t use browser-issued cookies or hidden form fields.

---

##### `/weatherForecast`
- **Method**: `GET`
- **Access**: Authenticated
- **Parameters**: None

```csharp
app.MapGet ("/weatherForecast", () =>
{
	var forecast = Enumerable.Range (1, 5).Select (index =>
		new WeatherForecast
		(
			DateOnly.FromDateTime (DateTime.Now.AddDays (index)),
			Random.Shared.Next (-20, 55),
			summaries[Random.Shared.Next (summaries.Length)]
		))
		.ToArray ();

	return forecast;
})
	.WithOpenApi ()
	.WithName ("GetWeatherForecast")
	.WithTags ("Weather")
	.WithSummary ("Weather Forecast")
	.WithDescription ("Returns a 5-day weather forecast with random temperatures and summaries.")
	.Produces<WeatherForecast[]> (StatusCodes.Status200OK)
	.Produces (StatusCodes.Status401Unauthorized);
```

🧠 **Purpose**: This endpoint generates and returns a mock 5-day weather forecast using the `WeatherForecast` DTO. Each entry includes a date, temperature range, and summary condition randomly selected from a predefined list.

It returns:

- An array of WeatherForecast objects.

This route is particularly helpful for:

- Demonstrating how minimal APIs deliver structured, typed collections.
- Testing dynamic data generation, DTO serialization, and OpenAPI annotations.
- Validating authenticated access to formatted content in development UIs such as Scalar.

## 👥 Seed Users & Roles

| Role	| Email				| Password	|
|-------|-------------------|-----------|
| Admin	| admin@example.com	| Admin!123	|
| User	| jiten@example.com	| User!123	|

🧠 **Purpose**: Seeding simplifies the development experience by providing ready-to-use test users with confirmed email status and predefined roles. This ensures:

- Immediate access to protected endpoints.
- Validation of role-based policies (`RequireRole("Admin")`).
- Smooth testing of login, token issuance, and refresh workflows.
- Confirmation that Identity configuration and database setup are correctly wired.

### 🔎 Configuration

```csharp
// RolesAndUserConfig.cs
public static class RolesAndUserConfig
{
	public static async Task SeedRolesAndUsersAsync (IServiceProvider serviceProvider)
	{
		var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>> ();
		var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>> ();

		// Define Roles
		string[] roles = [ "Admin", "User" ];

		// Create Roles if they don't exist
		foreach (var role in roles)
		{
			if (!await roleManager.RoleExistsAsync (role))
				await roleManager.CreateAsync (new IdentityRole (role));
		}

		// Create Users if they don't exist
		if (!userManager.Users.Any ())
		{
			// Create an Admin user
			var adminEmail = "admin@example.com";
			var adminUser = await userManager.FindByEmailAsync (adminEmail);
			if (adminUser is null)
			{
				adminUser = new ()
				{
					UserName = adminEmail,
					Email = adminEmail,
					EmailConfirmed = true
				};

				await userManager.CreateAsync (adminUser, "Admin!123");
				await userManager.AddToRoleAsync (adminUser, "Admin");
			}

			// Create a Normal user
			var userEmail = "jiten@example.com";
			var normalUser = await userManager.FindByEmailAsync (userEmail);
			if (normalUser is null)
			{
				normalUser = new ()
				{
					UserName = userEmail,
					Email = userEmail,
					EmailConfirmed = true,
					PhoneNumber = "9999 99999",
					PhoneNumberConfirmed = true
				};

				await userManager.CreateAsync (normalUser, "User!123");
				await userManager.AddToRoleAsync (normalUser, "User");
			}
		}
	}
}

// Program.cs
var app = builder.Build ();

if (app.Environment.IsDevelopment())
{
	// Seed Identity Users and Roles
	using var scope = app.Services.CreateScope();
	var services = scope.ServiceProvider;
	await RolesAndUserConfig.SeedRolesAndUsersAsync(services);
}
```

📌 **Note**: This logic runs only under `Development` environment, preventing test accounts from being seeded in production. It also checks the existing user store and role registry to avoid duplicates ensuring safe and idempotent startup behavior. Production setups should use structured onboarding flows with user registration and password policies tailored to your security model.

💡 To explore and test endpoints quickly, use the included [Requests.http](./BearerTokenAuthDemo/Requests.http) file. Learn how to send request parameters via Form. Launching the app also starts Scalar UI at `/scalar`.

## 📘 OpenAPI & Scalar UI Integration

ASP.NET Core minimal APIs offer built-in OpenAPI generation and a beautifully customizable Scalar UI. This setup enables live token-aware testing, clean endpoint visualization, and organized documentation flows.

🧠 **Purpose**: Provides structured metadata, interactive exploration, and secure Bearer token testing for all endpoints.

It supports:

- Tag-based grouping (`Auth`, `Home`, `Greeting`, `Weather`).
- Endpoint summaries, descriptions, and named routes.
- UI enhancements via Scalar settings.
- Downloadable OpenAPI spec in `openapi/v1.json`.
- Scoped access via Bearer tokens.

### 🔧 Configuration Snippet (Program.cs)

Refer to [📘 Configuring OpenAPI](#configuring-openapi) to see how I have setup the OpenAPI documentation.

```csharp
// ✅ Register OpenAPI support
builder.Services.AddOpenApi(...);

// ✅ Middleware: OpenAPI + Scalar UI (development only)
if (app.Environment.IsDevelopment())
{
    // Generate the OpenAPI spec
    app.MapOpenApi()
        .AllowAnonymous();

    app.MapScalarApiReference(options =>
    {
        options
            .WithSidebar(true)
            .WithTagSorter(TagSorter.Alpha)
            .WithLayout(ScalarLayout.Modern)
            .WithClientButton(false)
            .WithTheme(ScalarTheme.BluePlanet)
            .WithTitle("Bearer Token Identity Demo v1.0")
            .WithDownloadButton(true)
            .WithDefaultOpenAllTags(false)
            .WithFavicon("https://scalar.com/logo-light.svg")
            .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);

        options.Authentication = new ScalarAuthenticationOptions
        {
            PreferredSecuritySchemes = [ IdentityConstants.BearerScheme ]
        };
    })
    .AllowAnonymous();
}
```

📌 **Why `.AllowAnonymous()` Is Important**

Both `MapOpenApi()` and `MapScalarApiReference()` are flagged with `.AllowAnonymous()` to keep documentation publicly accessible even with global authorization enforced across all endpoints.

This ensures that:

- OpenAPI metadata is available for loading and rendering schema details.
- Scalar UI can load without triggering token authentication middleware.
- Developers and API consumers can onboard quickly, discover available routes, and test login flows without barriers.

✅ Once configured, every endpoint annotated with `.WithOpenApi()` and `.WithTags()` appears neatly organized in Scalar ready for testing, visualization, and client generation.

✅ To test protected routes in Scalar UI, paste the Bearer token in the top-right auth field. All endpoints will respect this token unless they've been marked as public.

## 🔄 Execution Flow: Identity + Bearer Token Request Lifecycle

```
🔐 Client authenticates by sending credentials to /api/Account/login
	→ Identity middleware processes the login attempt
		→ Applies lockout thresholds, email confirmation checks, and password policies
	→ On successful validation, access token and refresh token are issued

	Response JSON:
	{
		"tokenType": "Bearer",
		"accessToken": "CfDJ8Mow6tBau5xOiY-o5Esr...",
		"expiresIn": 3600,
		"refreshToken": "CfDJ8Mow6tBau5xOiY-o5Esr..."
	}

📨 Client includes access_token in Authorization header
	→ Header: Authorization: Bearer eyJ...

	🧠 Note:
	- Swagger & Scalar automatically prepend the word `Bearer ` (with a space) to the token
	- Tools like Postman, Insomnia, and `.http` files require you to manually write
		`Bearer CfDJ8Mow6tBau5xOiY-o5Esr...`

🛂 Protected endpoint (e.g. /greet) receives the request
	→ UseAuthentication middleware validates the token
		→ Checks signature, expiry, and scheme
	→ UseAuthorization middleware enforces policy
		→ Validates roles or claims
			→ If unauthorized → 403 Forbidden
			→ If valid → request proceeds to next step

📥 Query parameters or form input are bound to endpoint parameters
	→ Model binding populates inputs
	→ Validation checks for missing or malformed data
		→ If validation fails → 400 Bad Request

⚙️ Endpoint logic executes

    Example: `/greet?name=Jiten`

	Response JSON:
	{
		"message": "Hello, Jiten!"
	}

💥 If an exception occurs during execution
	→ Default ASP.NET Core behavior triggers
		→ Generic error response is returned
		→ ProblemDetails is **not returned automatically** for minimal APIs unless configured otherwise

📤 Final response is sent
	→ ✅ 200 OK — Success. The result was successfully returned.
	→ ⚠️ 400 Bad Request — Validation failure. No endpoints are currently programmed to return 400, as there is no validation logic in place. Additionally, Minimal endpoints do not return ProblemDetails out of the box unless explicitly configured.
	→ 🔐 401 Unauthorized — Missing or Invalid token.
	→ ⛔ 403 Forbidden — Policy or Role mismatch.
	→ 💥 500 Internal Server Error — Unhandled exceptions, if any.
```

## 📝 Remarks & Reference Notes

This repository demonstrates a fully self-contained Identity setup using ASP.NET Core minimal APIs complete with authentication, role-based access, OpenAPI metadata, and Scalar UI integration.

### 📚 Recommended Resources

- [ASP.NET Core Identity overview](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [Minimal APIs in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/minimal-apis)
- [OpenAPI Specification Guide](https://spec.openapis.org/oas/latest.html)
- [Scalar API Documentation](https://guides.scalar.com/scalar/introduction)

### 📌 Design Philosophy

This implementation is guided by clarity, modularity, and production-awareness. Each feature is purposefully structured to support maintainability, secure configuration, and streamlined developer experience.

The approach prioritizes:

- Minimalistic setup with expressive configuration.
- Annotated endpoints to support OpenAPI workflows.
- Role-based access control with scoped service lifetimes.
- Clean UI integration to support interactive and token-aware testing.

The architecture is intentionally lean, modular, and adaptable. Suitable for evolving identity requirements while keeping the implementation simple and maintainable.

---

🧭 *Stay Curious. Build Thoughtfully.*