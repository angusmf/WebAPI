using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApi.Helpers;

namespace WebApi.Services
{


    public class UserService 
    {
        private DataContext _context;

        public UserService(DataContext context)
        {
            _context = context;
        }

        public IdentityUser GetById(string id)
        {
            return _context.Users.Where(u => u.Id == id).SingleOrDefault();
        }
    }
}