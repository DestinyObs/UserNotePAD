using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace UserNotePAD.Models
{
    public class User : IdentityUser<int>
    {
        public string Occupation { get; set; }
        public string VerificationCode { get; set; }
        public bool IsVerified { get; set; } = false;
        public DateTime? VerificationCodeExpiration { get; set; }
        public string EmailNot { get; set; }

    }
}
