namespace JwtIdentity.Dtos;

public class UpdateTokenDto
{
#pragma warning disable CS8618
    public string AccessToken { get; set; }
#pragma warning restore CS8618
    public Guid RefreshToken { get; set; }
}