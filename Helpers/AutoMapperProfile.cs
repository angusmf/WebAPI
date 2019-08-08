using AutoMapper;
using Microsoft.AspNetCore.Identity;
using WebApi.Dtos;

namespace WebApi.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<IdentityUser, UserDto>();
            CreateMap<UserDto, IdentityUser>();
        }
    }
}