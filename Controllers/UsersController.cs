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

    

        [Authorize(Roles = "Admin", AuthenticationSchemes = "Bearer")]
        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _context.Users;
            var userDtos = _mapper.Map<IList<UserDto>>(users);
            return Ok(userDtos);
        }



        [Authorize(Roles = "Admin", AuthenticationSchemes = "Bearer")]
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

        [Authorize(Roles = "Admin", AuthenticationSchemes = "Bearer")]
        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            var user = _context.Users.Where(u => u.Id == id).SingleOrDefault();
            _userManager.DeleteAsync(user);
            _context.SaveChanges();
            return Ok();
        }

        [Authorize(Roles = "Player,Admin", AuthenticationSchemes = "Bearer")]
        [HttpGet("id")]
        public async Task<IActionResult> GetId()
        {
            var userId = User.FindFirstValue(ClaimTypes.Name);
            var user = await _userManager.FindByIdAsync(userId);
            var userDto = _mapper.Map<UserDto>(user);
            return Ok(userDto);
        }
    }
}
