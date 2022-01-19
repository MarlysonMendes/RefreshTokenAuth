using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using RefreshTokenAuth.Models;
using System.Security.Claims;
using RefreshTokenAuth;
using System.Security.Cryptography;

namespace RefreshTokenAuth.Services
{
    public static class TokenService
    {

        public static string GenerateToken(User user)
        {
            var TokenHandler = new JwtSecurityTokenHandler();
            var Key = Encoding.ASCII.GetBytes(Settigns.Secret);
            var TokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Key), SecurityAlgorithms.HmacSha256Signature),

            };
            var token = TokenHandler.CreateToken(TokenDescription);
            return TokenHandler.WriteToken(token);
        }

        public static string GenerateToken(IEnumerable<Claim> claims)
        {
            var TokenHandler = new JwtSecurityTokenHandler();
            var Key = Encoding.ASCII.GetBytes(Settigns.Secret);
            var TokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Key), SecurityAlgorithms.HmacSha256Signature),

            };
            var token = TokenHandler.CreateToken(TokenDescription);
            return TokenHandler.WriteToken(token);
        }


        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Settigns.Secret)),
                ValidateLifetime = false,
            };
            var TokenHandler = new JwtSecurityTokenHandler();
            var principal = TokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            if(securityToken is not JwtSecurityToken jwtSecurityToken || 
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, 
            StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;
        }

        private static List<(string, string)> _refreshTokens = new ();

        public static void SaveRefreshToken(string username, string refreshToken)
        {
            _refreshTokens.Add(new(username,refreshToken));
        }
        public static string GetRefreshToken(string username)
        {
            return _refreshTokens.FirstOrDefault(x => x.Item1 == username).Item2;
        }
        public static void DeleteRefreshToken(string username, string refreshToken)
        {
            var item = _refreshTokens.FirstOrDefault(x => x.Item1 == username
            && x.Item2 == refreshToken);
            _refreshTokens.Remove(item);
        }


    }
}