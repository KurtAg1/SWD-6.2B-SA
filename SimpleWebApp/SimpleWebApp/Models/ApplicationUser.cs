using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace SimpleWebApp.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        string Name { get; set; }

        public virtual ICollection<Note> Notes { get; set; }
    }
}
