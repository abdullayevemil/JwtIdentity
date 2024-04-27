namespace JwtIdentity.Models;

using Microsoft.AspNetCore.Identity;

public class User : IdentityUser
{
    public int? Age { get; set; }
    public string? Surname { get; set; }
}