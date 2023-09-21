using ChatBIDApp.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Text;
using UserNotePAD.Data;
using UserNotePAD.Models;
using UserNotePAD.ViewModels;
using static System.Net.WebRequestMethods;

namespace UserNotePAD.Controllers.Account
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly SmtpSettings _smtpSettings;
        private readonly NotePadDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager, IOptions<SmtpSettings> smtpSettings, NotePadDbContext dbContext, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _smtpSettings = smtpSettings.Value;
            _dbContext = dbContext;
            _configuration = configuration;
        }

        public IActionResult Register()
        {
            var response = new UserRegistrationDto();
            return View(response);
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }


        [HttpPost]
        public async Task<IActionResult> Register(UserRegistrationDto userDto)
        {
            try
            {
                string otp = GenerateOTP();

                // Check if the password and confirm password match
                if (userDto.Password != userDto.ConfirmPassword)
                {
                    ModelState.AddModelError("ConfirmPassword", "The password and confirmation password do not match.");

                    return View(userDto); // Return the view with validation errors
                }

                // Create a new user with email, password, and occupation
                var user = new User
                {
                    UserName = userDto.UserName,
                    PasswordHash = userDto.Password,
                    Email = userDto.Email,
                    Occupation = userDto.Occupation // Add the occupation field
                };

                // Check if email already exists
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser != null)
                {
                    ModelState.AddModelError("Email", "Email already exists.");
                    return View(userDto); // Return the view with validation errors
                }

                // Create user with password
                var result = await _userManager.CreateAsync(user, userDto.Password);

                if (result.Succeeded)
                {
                    bool otpSent = false;
                    // Send OTP
                    otpSent = SendOTPViaEmail(user.Email, otp);

                    if (!otpSent)
                    {
                        return StatusCode((int)HttpStatusCode.InternalServerError, "Failed to send OTP. Please try again later.");
                    }

                    // Redirect to the "Index" page after successful registration
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Registration failed. Please check the provided information.");
                    return View(userDto); 
                }
            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.InternalServerError, ex.Message);
            }
        }



        private string GenerateJwtToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>{
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            };
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(100), // Token expiration time (adjust as needed)
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        private string GenerateOTP()
        {
            Random random = new Random();
            int otpValue = random.Next(100000, 999999);
            return otpValue.ToString();
        }
        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);


                return addr.Address == email && email.Contains(".") && email.Contains("@");
            }
            catch
            {
                return false;
            }
        }
        private bool SendEmail(string email, string subject, string body)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;

                mail.From = new MailAddress(_smtpSettings.Username);
                mail.To.Add(email);
                mail.Subject = subject;
                mail.Body = body;

                smtpClient.Send(mail);

                return true;
            }
            catch (Exception ex)
            {
                // Handle the exception
                return false;
            }
        }
        private bool SendOTPViaEmail(string email, string otp)
        {
            try
            {
                MailMessage mail = new MailMessage();
                SmtpClient smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port);
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password);
                smtpClient.EnableSsl = true;

                mail.From = new MailAddress("NoReply@TextBID.com");
                mail.To.Add(email);
                mail.Subject = "OTP Verification";
                mail.Body = $"Your OTP is: {otp}";

                smtpClient.Send(mail);

                // Set the verification code expiration time to 10 minutes from now
                TimeSpan codeExpirationTime = TimeSpan.FromMinutes(10);

                var user = _dbContext.Users.SingleOrDefault(u => u.Email == email);

                return true;
            }
            catch (Exception ex)
            {
                // Handle the exception
                return false;
            }
        }
    }
}
