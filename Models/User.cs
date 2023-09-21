using Microsoft.AspNetCore.Identity;

namespace UserNotePAD.Models
{
    public class User : IdentityUser<int>
    {
        public string ProfilePhotoUrl { get; set; }
        public string Occupation { get; set; }

    }
}
