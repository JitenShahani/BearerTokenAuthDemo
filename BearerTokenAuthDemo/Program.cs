var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Enable detailed authentication/authorization logging for troubleshooting
builder.Logging
	.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug)
	.AddFilter("Microsoft.AspNetCore.Authorization", LogLevel.Debug);

// Configure Entity Framework Core with SQLite
builder.Services
	.AddDbContext<AppDbContext>(options =>
	{
		options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
		options.EnableDetailedErrors();
		options.EnableSensitiveDataLogging();
	});

// Configure Identity Services
builder.Services
	.AddIdentityCore<IdentityUser>(options =>
	{
		// User Settings
		options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
		options.User.RequireUniqueEmail = true;

		// Password Settings
		options.Password.RequireDigit = true;
		options.Password.RequireNonAlphanumeric = true;
		options.Password.RequireUppercase = true;
		options.Password.RequireLowercase = true;

		// Lockout Settings
		options.Lockout.MaxFailedAccessAttempts = 5;
		options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

		// SignIn Settings
		options.SignIn.RequireConfirmedEmail = true;
	})
	.AddRoles<IdentityRole>()
	.AddEntityFrameworkStores<AppDbContext>()
	.AddApiEndpoints();

// Configure Authentication
builder.Services
	.AddAuthentication()
	.AddBearerToken(IdentityConstants.BearerScheme, options =>
	{
		// Set token expiration to 1 hour - Default Value
		options.BearerTokenExpiration = TimeSpan.FromSeconds(3600);

		// Set Refresh token expiration to 2 hours
		options.RefreshTokenExpiration = TimeSpan.FromSeconds(7200);
	});

// Configure Authorization
/*
	- The DefaultPolicy ensures that all requests require authentication.
	- Any endpoint without a specific policy will automatically enforce authentication.
	- If an endpoint needs to be public, explicitly override using .AllowAnonymous().
*/
builder.Services.AddAuthorization(options =>
{
	options.DefaultPolicy = new AuthorizationPolicyBuilder()
		.RequireAuthenticatedUser()
		.AddAuthenticationSchemes(IdentityConstants.BearerScheme)
		.Build();

	options.FallbackPolicy = options.DefaultPolicy;
});

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi(options =>
{
	options.AddDocumentTransformer(async (document, context, cancellationToken) =>
	{
		// Configure OpenAPI Document
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

		// Configure Tags
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
				Description = "Endpoint for greeting users based on the input value.",
			}
		];

		// Configure Security Schemes
		var service = context.ApplicationServices.GetRequiredService<IAuthenticationSchemeProvider>();

		var schemes = await service.GetAllSchemesAsync();

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
					BearerFormat = "Opaque"
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

// Configure Identity Options - Handled in AddIdentityCore above, but can be configured here as well if needed
//builder.Services.Configure<IdentityOptions> (options =>
//{
//	// User Settings
//	options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
//	options.User.RequireUniqueEmail = true;

//	// Password Settings
//	options.Password.RequireDigit = true;
//	options.Password.RequireNonAlphanumeric = true;
//	options.Password.RequireUppercase = true;
//	options.Password.RequireLowercase = true;

//	// Lockout Settings
//	options.Lockout.MaxFailedAccessAttempts = 5;
//	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes (5);

//	// SignIn Settings
//	options.SignIn.RequireConfirmedEmail = true;
//});

// Configure Bearer Token Options - Handled in AddBearerToken above, but can be configured here as well if needed
//builder.Services.Configure<BearerTokenOptions> (options =>
//{
//	options.BearerTokenExpiration = TimeSpan.FromSeconds (7200);
//});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	// Seed Identity Users and Roles
	using var scope = app.Services.CreateScope();
	var services = scope.ServiceProvider;
	await RolesAndUserConfig.SeedRolesAndUsersAsync(services);
}

// Configure the HTTP request pipeline.

// Enable Authentication
app.UseAuthentication();

// Enable Authorization
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
	app.MapOpenApi()
		.AllowAnonymous();

	// Configure Scalar
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
			PreferredSecuritySchemes = [IdentityConstants.BearerScheme]
		};
	})
		.AllowAnonymous();
}

app.UseHttpsRedirection();

app
.MapGroup("/api/Account")
.MapIdentityApi<IdentityUser>()
.WithOpenApi()
.WithTags("Auth")
.WithDescription("Endpoints for managing user accounts, including registration, login, and profile management.")
.AllowAnonymous();

// Map MyEndpoints
new Endpoints().MapMyEndpoints(app);

app.Run();