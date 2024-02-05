using Lib.DTOs;
using Lib.Entities;
using Lib.Responses;

namespace LibServer.Repositories.Contracts
{
    public interface IUserAccount
    {
        Task<GeneralResponse> CreateAsync(RegisterDto user);
        Task<LoginResponse> SignInAsync(LoginDto user);
        Task<LoginResponse> RefreshTokenAsync(RefreshTokenDto token);
    }
}
