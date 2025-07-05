namespace BearerTokenAuthDemo;

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
					PhoneNumber = "99999 99999",
					PhoneNumberConfirmed = true
				};

				await userManager.CreateAsync (normalUser, "User!123");
				await userManager.AddToRoleAsync (normalUser, "User");
			}
		}
	}
}