using Lib.DTOs;
using Lib.Entities;
using Lib.Responses;
using LibServer.Data;
using LibServer.Helpers;
using LibServer.Repositories.Contracts;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace LibServer.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext db) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(RegisterDto user)
        {
            if (user is null) return new GeneralResponse(false, "Model vazia.");

            var checkUser = await FindUserByEmail(user.Email!);
            if (checkUser is not null) return new GeneralResponse(false, "Usuário existente.");

            var applicationUser = await AddToDatabase(new ApplicationUser()
            {
                Fullname = user.Fullname,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password),
            });

            var checkAdminRole = await db.SystemRoles.FirstOrDefaultAsync(x => x.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
                await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "Conta criada com sucesso!");
            }

            var checkUserRole = await db.SystemRoles.FirstOrDefaultAsync(x => x.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole() { Name = Constants.User });
                await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
            }
            else
            {
                await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
            }
            return new GeneralResponse(true, "Conta criada com sucesso!");

        }
        public async Task<LoginResponse> SignInAsync(LoginDto user)
        {
            if (user is null) return new LoginResponse(false, "Model vazia.");

            var applicationUser = await FindUserByEmail(user.Email!);
            if (applicationUser is null) return new LoginResponse(false, "Usuário não existe.");

            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
            {
                return new LoginResponse(false, "Email ou senha inválidos");
            }

            var getUserRole = await db.UserRoles.FirstOrDefaultAsync(x => x.UserId == applicationUser.Id);
            if (getUserRole is null)
            {
                return new LoginResponse(false, "Role do usuário não existe.");
            }

            var getRoleName = await db.SystemRoles.FirstOrDefaultAsync(x => x.Id == getUserRole.Id);
            if (getRoleName is null)
            {
                return new LoginResponse(false, "Role do usuário não existe.");
            }

            string jwtToken = GenerateToken(applicationUser, getRoleName!.Name);
            string refreshToken = GenerateRefreshToken();
            return new LoginResponse(true, "Login feito com sucesso.", jwtToken, refreshToken);

        }
        public async Task<LoginResponse> RefreshTokenAsync(RefreshTokenDto token)
        {
            if (token is null) return new LoginResponse(false, "Model vazia");

            var findToken = await db.RefreshTokenInfos.FirstOrDefaultAsync(x => x.Token!.Equals(token.Token));
            if(findToken is null) return new LoginResponse(false, "Token inválido.");

            var user = await db.ApplicationUsers.FirstOrDefaultAsync(x => x.Id == findToken.Id);
            if (user is null) return new LoginResponse(false, "Usuário não existe.");

            var userRole = await FindUserRole(user.Id);
            var roleName = await FindRoleName(userRole.RoleId);
            string jwtToken = GenerateToken(user, roleName.Name!);
            string refreshToken = GenerateRefreshToken();

            var updateRefreshToken = await db.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (updateRefreshToken is null) return new LoginResponse(false, "Refresh Token não pôde ser gerado porque o usuário não fez login");

            updateRefreshToken.Token = refreshToken;
            await db.SaveChangesAsync();
            return new LoginResponse(true, "Refresh Token gerado com sucesso", jwtToken, refreshToken);
        }
        private string GenerateToken(ApplicationUser user, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Fullname!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role),
            };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private async Task<UserRole> FindUserRole(int userId)
        {
            return await db.UserRoles.FirstOrDefaultAsync(x => x.UserId == userId);
        }
        private async Task<SystemRole> FindRoleName(int roleId)
        {
            return await db.SystemRoles.FirstOrDefaultAsync(x => x.Id == roleId);
        }
        private async Task<ApplicationUser> FindUserByEmail(string email) =>
            await db.ApplicationUsers.FirstOrDefaultAsync(u => u.Email!.ToLower()!.Equals(email!.ToLower()));
        private static string GenerateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }
        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = db.Add(model!);
            await db.SaveChangesAsync();
            return (T)result.Entity;
        }
    }
}
