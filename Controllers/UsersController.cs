using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using AutoMapper;
using System.IdentityModel.Tokens.Jwt;
using WebApi.Helpers;
using Microsoft.Extensions.Options;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using WebApi.Services;
using WebApi.Dtos;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Linq;

namespace WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IMapper _mapper;
        private readonly AppSettings _appSettings;
        private UserManager<IdentityUser> _userManager;
        private readonly DataContext _context;

        public UsersController(
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            UserManager<IdentityUser> userManager,
            DataContext context)
        {
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _userManager = userManager;
            _context = context;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public async Task<IActionResult> AuthenticateAsync([FromBody]UserDto userDto)
        {
            if (string.IsNullOrEmpty(userDto.Username) || string.IsNullOrEmpty(userDto.Password))
                return null;

            var user = _context.Users.Where(u => u.UserName == userDto.Username).SingleOrDefault();

            var passwordValidator = new PasswordValidator<IdentityUser>();
            var result = await passwordValidator.ValidateAsync(_userManager, user, userDto.Password);

            if (!result.Succeeded)
            {
                //invalid login
                return BadRequest(new { message = "Username or password is incorrect" });
            }


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
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // return basic user info (without password) and token to store client side
            return Ok(new
            {
                Id = user.Id,
                Username = user.UserName,
                Token = tokenString
            });
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]UserDto userDto)
        {
            // map dto to entity
            var user = _mapper.Map<IdentityUser>(userDto);

            try 
            {
                // save 
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "Player");
                }
                _context.SaveChanges();
                return Ok();
            } 
            catch(AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Admin", AuthenticationSchemes = "Bearer")]
        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _context.Users;
            var userDtos = _mapper.Map<IList<UserDto>>(users);
            return Ok(userDtos);
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("{id}")]
        public IActionResult GetById(string id)
        {
            var user = _context.Users.Where(u => u.Id == id).SingleOrDefault();
            var userDto = _mapper.Map<UserDto>(user);
            return Ok(userDto);
        }

        [Authorize(Roles = "Admin")]
        [HttpPut("{id}")]
        public IActionResult Update(string id, [FromBody]UserDto userDto)
        {
            // map dto to entity and set id
            var user = _mapper.Map<IdentityUser>(userDto);
            user.Id = id;

            try 
            {
                // save 
                _context.Update(_context.Users.Where(u => u.Id == id).SingleOrDefault());
                _context.SaveChanges();
                return Ok();
            } 
            catch(AppException ex)
            {
                // return error message if there was an exception
                return BadRequest(new { message = ex.Message });
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            var user = _context.Users.Where(u => u.Id == id).SingleOrDefault();
            _userManager.DeleteAsync(user);
            _context.SaveChanges();
            return Ok();
        }

        [HttpGet("id")]
        public IActionResult GetId()
        {
            var userId = User.FindFirstValue(ClaimTypes.Name);
            var user = _userManager.FindByIdAsync(userId);
            var role = _userManager.GetRolesAsync(user.Result);
            return Ok(userId);
        }
    }
}
