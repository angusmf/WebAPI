using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using WebApi.Helpers;
using Microsoft.Extensions.Options;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Linq;
using WebApi.Models;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;

namespace WebApi.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppSettings _appSettings;
        private UserManager<IdentityUser> _userManager;
        private readonly DataContext _context;

        public AuthController(
           IOptions<AppSettings> appSettings,
           UserManager<IdentityUser> userManager,
           DataContext context)
        {
            _appSettings = appSettings.Value;
            _userManager = userManager;
            _context = context;
        }

        [AllowAnonymous]
        [HttpPost("google")]
        public async Task<IActionResult> Google([FromBody]UserView userView)
        {
            try
            {
                var payload = GoogleJsonWebSignature.ValidateAsync(userView.TokenId, new GoogleJsonWebSignature.ValidationSettings()).Result;

                if (payload == null || payload.Email == null)
                {
                    return BadRequest(new { message = "Validation failed" });
                }

                var user = _context.Users.Where(u => u.UserName == payload.Email).SingleOrDefault();

                //if user not found, register them
                if (user == null)
                {
                    try
                    {
                        user = await Register(payload);
                    }
                    catch (AppException ex)
                    {

                        // return error message if there was an exception
                        return BadRequest(new { message = ex.Message });
                    }
                }

                //Check lockout
                if (_userManager.IsLockedOutAsync(user).Result) return StatusCode(StatusCodes.Status403Forbidden, "User locked out");


                List<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Name, user.Id));

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
                var roles = await _userManager.GetRolesAsync(user);
                foreach (string role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims.ToArray()),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                // return basic user info (without password) and token to store client side
                return Ok(new AuthToken() { Token = tokenString });


            }
            catch (Exception ex)
            {
                BadRequest(ex.Message);
            }
            return BadRequest();
        }

        async Task<IdentityUser> Register(GoogleJsonWebSignature.Payload payload)
        {

            var user = new IdentityUser() { UserName = payload.Email };

            // save 
            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Player");
            }
            _context.SaveChanges();
            return user;
 
        }

    }
}