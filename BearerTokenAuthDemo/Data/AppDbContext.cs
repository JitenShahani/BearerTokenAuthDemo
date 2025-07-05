namespace BearerTokenAuthDemo.Data;

public class AppDbContext : IdentityDbContext<IdentityUser>
{
	public AppDbContext (DbContextOptions options) : base (options) { }
}