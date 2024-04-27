namespace JwtIdentity.Dtos;

public class LoginDto
{
    public string? Email { get; set; }
    public string? Password { get; set; }
    public IEnumerable<string>? Roles { get; set; }
}