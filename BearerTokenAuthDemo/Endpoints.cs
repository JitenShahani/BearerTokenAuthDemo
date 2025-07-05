namespace BearerTokenAuthDemo;

public class Endpoints
{
	public void MapMyEndpoints (IEndpointRouteBuilder app)
	{
		var homeGroup = app.MapGroup ("/")
			.WithOpenApi ()
			.WithTags ("Home")
			.RequireAuthorization();

		var greetGroup = app.MapGroup ("/greet")
			.WithOpenApi ()
			.WithTags ("Greeting")
			.RequireAuthorization ();

		homeGroup.MapGet ("/getToken", (HttpContext httpContext) =>
		{
			var requestToken =
				httpContext.Request.Headers["Authorization"].ToString ().Replace ("Bearer ", "");

			// You could also directly access the Authorization object/dictionary under request headers.
			// var requestToken = httpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");

			return TypedResults.Ok(new { authToken = requestToken });
		})
			.WithSummary ("Get Authorization Token")
			.WithDescription ("Endpoint to retrieve an authentication token for the user.")
			.Produces (StatusCodes.Status200OK)
			.Produces (StatusCodes.Status401Unauthorized);

		homeGroup.MapGet ("/admin", () => TypedResults.Ok (new { Message = "Welcome, Admin!" }))
			.WithSummary ("Admin Only")
			.WithDescription ("This endpoint is accessible only to users with the Admin role.")
			.RequireAuthorization (policy => policy.RequireRole ("Admin"))
			.Produces (StatusCodes.Status200OK)
			.Produces (StatusCodes.Status401Unauthorized)
			.Produces (StatusCodes.Status403Forbidden);

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

		homeGroup.MapGet ("/noAuthRequired", () => TypedResults.Ok (new { Message = "Hello, from `Auth Not Required` endpoint..." }))
			.WithSummary ("Auth Not Required")
			.WithDescription ("Authentication is not required!")
			.AllowAnonymous ()
			.Produces (StatusCodes.Status200OK);

		homeGroup.MapPost ("/form-input", ([FromForm] Shirt shirt) => TypedResults.Ok (shirt))
			.WithSummary ("Create a new Shirt using Form Data")
			.WithDescription ("This endpoint helps create a new shirt using the Form data.")
			.Produces (StatusCodes.Status200OK)
			.DisableAntiforgery ();

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

		string[] summaries = ["Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"];

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
	}
}