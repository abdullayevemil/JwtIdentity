namespace JwtIdentity.Dtos;

public class RegistrationDto
{
    public string? Name { get; set; }
    public string? Surname { get; set; }
    public int? Age { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
    public IEnumerable<string>? Roles { get; set; }
}