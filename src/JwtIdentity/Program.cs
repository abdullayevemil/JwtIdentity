using System.Reflection;
using JwtIdentity.Data;
using JwtIdentity.Models;
using JwtIdentity.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

var jwtOptionsSection = builder.Configuration.GetSection("JwtOptions");

var jwtOptions = jwtOptionsSection.Get<JwtOptions>() ?? throw new Exception("Couldn't create jwt options object");

builder.Services.Configure<JwtOptions>(jwtOptionsSection);

builder.Services.AddAuthorization();

var connectionString = builder.Configuration.GetConnectionString("FitnessDb");

builder.Services.AddDbContext<JwtIdentityDbContext>(dbContextOptionsBuilder =>
{
    dbContextOptionsBuilder.UseNpgsql(connectionString, o =>
    {
        o.MigrationsAssembly(Assembly.GetExecutingAssembly().FullName);
    });
});

builder.Services.AddIdentity<User, IdentityRole>(options => {
    options.Password.RequireNonAlphanumeric = true;
})
    .AddEntityFrameworkStores<JwtIdentityDbContext>();

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(jwtOptions.KeyInBytes),

            ValidateLifetime = true,

            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,

            ValidateIssuer = true,
            ValidIssuers = jwtOptions.Issuers,
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddSwaggerGen(options =>
{
    const string scheme = "Bearer";

    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Jwt Identity API",
        Version = "v1"
    });

    options.AddSecurityDefinition(
        name: scheme,

        new OpenApiSecurityScheme() {
            Description = "Enter here jwt token with Bearer",
            In = ParameterLocation.Header,
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            Scheme = scheme
        });

    options.AddSecurityRequirement(
        new OpenApiSecurityRequirement() {
            {
                new OpenApiSecurityScheme() {
                    Reference = new OpenApiReference() {
                        Id = scheme,
                        Type = ReferenceType.SecurityScheme
                    }
                } ,
                new string[] {}
            }
        }
    );
});

builder.Services.AddCors(options => {
    options.AddPolicy("BlazorWasmPolicy", corsBuilder => {
        corsBuilder
            .WithOrigins("http://localhost:5160", "http://localhost:5141")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope()) {
    var dbContext = scope.ServiceProvider.GetRequiredService<JwtIdentityDbContext>();
    
    await dbContext.Database.MigrateAsync();
    
    await dbContext.Database.EnsureCreatedAsync();

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    await roleManager.CreateAsync(new IdentityRole(DefaultRoles.User.ToString()));

    await roleManager.CreateAsync(new IdentityRole(DefaultRoles.Admin.ToString()));
    
    await roleManager.CreateAsync(new IdentityRole(DefaultRoles.Moderator.ToString()));
    
    await roleManager.CreateAsync(new IdentityRole(DefaultRoles.Trainer.ToString()));
    
    await roleManager.CreateAsync(new IdentityRole(DefaultRoles.Nutritionist.ToString()));

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();

    var admin = new User{
        Age = 30,
        UserName = "Admin",
        Surname = "Admin",
        Email = "admin@gmail.com",   
    };

    await userManager.CreateAsync(admin, "Admin123!");

    await userManager.AddToRoleAsync(admin, DefaultRoles.Admin.ToString());
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();

    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.UseCors("BlazorWasmPolicy");

app.Run();