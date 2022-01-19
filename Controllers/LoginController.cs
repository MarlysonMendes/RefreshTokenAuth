using RefreshTokenAuth.Models;
using RefreshTokenAuth.Repositories;
using RefreshTokenAuth.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace ApiAuth.Controllers
{
    [ApiController]
    [Route("v1")]
    public class LoginController : ControllerBase
    {

        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<dynamic>> AuthenticateAsync([FromBody] User user)
        {
            var userLogin = UserRepository.GetUser(user.Username, user.Password);

            if (userLogin == null)
                return NotFound(new { message = "Usuário ou senha inválidos" });

            var token = TokenService.GenerateToken(userLogin);
            var refreshToken = TokenService.GenerateRefreshToken();
            TokenService.SaveRefreshToken(userLogin.Username, refreshToken);
            //apaga a senha do usuário para não retornar no token
            userLogin.Password = "";
            return new
            {
               user = userLogin,
               token = token,
               refreshToken = refreshToken
            };
        }

        public IActionResult RefreshToken(string token, string refreshToken)
        {
            var principal = TokenService.GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name;
            var savedRefreshToken = TokenService.GetRefreshToken(username);
            if(savedRefreshToken != refreshToken)
                throw new SecurityTokenException("Invalid refresh token");
        
            var newJwtToken = TokenService.GenerateToken(principal.Claims);
            var newRefreshToken = TokenService.GenerateRefreshToken();
            TokenService.DeleteRefreshToken(username, refreshToken);
            TokenService.SaveRefreshToken(username, newRefreshToken);
            return new ObjectResult(new
            {
                token = newJwtToken,
                refreshToken = newJwtToken
            });
        }
    }
}