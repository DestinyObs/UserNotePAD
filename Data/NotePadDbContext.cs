using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using UserNotePAD.Models;

namespace UserNotePAD.Data
{
    public class NotePadDbContext : IdentityDbContext<User, IdentityRole<int>, int>
    {
        public NotePadDbContext(DbContextOptions options) : base(options)
        {

        }

        public DbSet<Note> Notes { get; set; }
        public DbSet<User> Users { get; set; }
    }
}
