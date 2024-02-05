using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using LibServer.Repositories.Contracts;
using Lib.DTOs;
using Lib.Entities;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IUserAccount userAccountRepository) : Controller
    {
        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync(RegisterDto user)
        {
            if (user is null) return BadRequest("Model vazia");
            var result = await userAccountRepository.CreateAsync(user);
            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(LoginDto user)
        {
            if (user is null) return BadRequest("Model vazia");
            var result = await userAccountRepository.SignInAsync(user);
            return Ok(result);
        }
    }
}
