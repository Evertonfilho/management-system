using Lib.DTOs;
using Lib.Responses;

namespace LibClient.Services.Contracts
{
    public interface IUserAccountService
    {
        Task<GeneralResponse> CreateAsync(RegisterDto user);
        Task<LoginResponse> SignInAsync(LoginDto user);
        Task<LoginResponse> RefreshTokenAsync(RefreshTokenDto token);
    }
}
