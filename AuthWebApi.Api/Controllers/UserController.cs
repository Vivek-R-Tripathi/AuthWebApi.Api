using AuthWebApi.Api.Context;
using AuthWebApi.Api.Helper;
using AuthWebApi.Api.Model;
using AuthWebApi.Api.Model.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthWebApi.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _appDbContext;
        public UserController(AppDbContext appDbContext) {

            _appDbContext = appDbContext;
        }

        //Authentication user api or login api 

        [HttpPost("Authentication")]
        public async Task<IActionResult> Authentication([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _appDbContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);

            if (user == null)
                return NotFound(new { Message = "User Not Found !!" });

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                return BadRequest(new { Message = "Passsword is incorrect!!" });

            user.Token = CreateJwt(user);
            var accessToken = user.Token;
            var refreshToken = CreateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.Now.AddDays(5);
            await _appDbContext.SaveChangesAsync();

            return Ok(new TokenApiDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        //Add new user to Api

        [HttpPost("Registration")]
        public async Task<IActionResult> Register([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            // check user email address exist
            if (await CheckEmailAddressExist(userObj.Email))
            {
                return BadRequest(new { Message = "User Email Address Exist !!" });
            }

            //check password Strenght
            var pass = CheckPasswordStrenght(userObj.Password);

            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = Helper.PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "Admin";
            userObj.Token = "";

            //check user exist
            if (await CheckUserNameExist(userObj.UserName))
            {
                return BadRequest(new { Message = "User Alreay Exist!!" });
            }

            _appDbContext.Users.Add(userObj);

            await _appDbContext.SaveChangesAsync();


            return Ok(new { Message = "User Registration Successful" });

        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipleFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _appDbContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiry <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _appDbContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }


        //Get list of User
        [Authorize]
        [HttpGet("GetAllUser")]
        public async Task<List<User>> GetUserDetails()
        {
            return await _appDbContext.Users.ToListAsync();
        }

        //
        private async Task<bool> CheckEmailAddressExist(string email)
        {
            return await _appDbContext.Users.AnyAsync(x => x.Email == email);
        }

        private async Task<bool> CheckUserNameExist(string userName)
        {
            return await _appDbContext.Users.AnyAsync(x => x.UserName == userName);
        }

        private string CheckPasswordStrenght(string password)
        {
            StringBuilder sb = new StringBuilder();

            if (password.Length < 9)
                sb.Append("Password should be greater than 9 character" + Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be alpha numeric" + Environment.NewLine);

            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special charcter" + Environment.NewLine);

            return sb.ToString();
        }


        //JWT Creation method
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysceret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{user.UserName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }


        //Method for Refresh JWT Token
        private string CreateRefreshToken()
        {
            // Generate a random number
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            //convert it into base 64 dtring
            var refreshToken = Convert.ToBase64String(tokenBytes);

            //check wheather token exist or not
            var tokenInUsers = _appDbContext.Users.Any(x => x.RefreshToken == refreshToken);

            if (tokenInUsers)
            {
                return CreateRefreshToken();
            }

            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysceret.....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is Invalid Token");
            return principal;

        }

    }
}
