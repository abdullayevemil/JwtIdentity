FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY JwtIdentity.sln ./
COPY src/JwtIdentity/JwtIdentity.csproj src/JwtIdentity/
RUN dotnet restore src/JwtIdentity/JwtIdentity.csproj

COPY . .
RUN dotnet publish src/JwtIdentity/JwtIdentity.csproj -c Release -o /app/dist --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

COPY --from=build /app/dist .

EXPOSE 8080

ENTRYPOINT ["dotnet", "JwtIdentity.dll"]
