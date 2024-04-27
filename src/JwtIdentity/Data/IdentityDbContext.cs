namespace JwtIdentity.Data;

using JwtIdentity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class JwtIdentityDbContext(DbContextOptions<JwtIdentityDbContext> options) : IdentityDbContext<User, IdentityRole, string>(options)
{
    public DbSet<RefreshToken> RefreshTokens { get; set; }
}