﻿
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
using UserNotePAD.ViewModels.Dto;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc.ViewEngines;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace UserNotePAD.Controllers.Account
{
    public class AccountController : Controller
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ICompositeViewEngine _razorViewEngine;
        private readonly ITempDataProvider _tempDataProvider;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly SmtpSettings _smtpSettings;
        private readonly NotePadDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager, IOptions<SmtpSettings> smtpSettings, NotePadDbContext dbContext, IConfiguration configuration, IServiceProvider serviceProvider, ICompositeViewEngine razorViewEngine, ITempDataProvider tempDataProvider)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _smtpSettings = smtpSettings.Value;
            _dbContext = dbContext;
            _configuration = configuration;
            _serviceProvider = serviceProvider;
            _razorViewEngine = razorViewEngine;
            _tempDataProvider = tempDataProvider;
        }

        [HttpGet("verify")]
        public IActionResult Verify()
        {
            return View("Verify","Account");
        }

        [HttpGet("EmailNot")]
        public IActionResult EmailNot()
        {
            return View("EmailNot"); 
        }

        public IActionResult Register()
        {
            var response = new UserRegistrationDto();
            return View(response);
        }


        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            // Sign out the user
            await _signInManager.SignOutAsync();

            // Optionally, you can clear the user's session and cookies
            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Redirect to the home page or another desired page
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
                    Email = userDto.Email.ToLowerInvariant(),
                    Occupation = userDto.Occupation,
                    VerificationCode = otp,
                    VerificationCodeExpiration = DateTime.UtcNow.AddMinutes(20),
                    EmailNot = userDto.Email
                };

                // Check if email already exists
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser != null)
                {
                    ModelState.AddModelError("Email", "Email already exists.");
                    return View(userDto); // Return the view with validation errors
                }

                // Create user with password
                var result = await _userManager.CreateAsync(user);

                if (result.Succeeded)

                {
                    // Render the EmailNot.cshtml view to get the HTML content
                    var emailHtml = await RenderViewToStringAsync("EmailNot", user);

                    // Replace a placeholder in the HTML content with the OTP
                    emailHtml = emailHtml.Replace("{{VerificationLink}}", "https://localhost:7137/verify?code=" + user.VerificationCode);

                    // Send the email with the modified HTML content
                    bool otpSent = false;

                    otpSent = SendEmail(user.Email, "Email Verification", emailHtml);

                    if (!otpSent)
                    {
                        return StatusCode((int)HttpStatusCode.InternalServerError, "Failed to send OTP email. Please try again later.");
                    }

                    // Redirect to the "Index" page after successful registration
                    return RedirectToAction("Verify", "Account");
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

        public IActionResult Login()
        {
            var response = new LoginDto();
            return View(response);
        }

        [HttpPost("Account/Login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDto loginDto, bool rememberMe)
        {
            try
            {
                // Try to find the user by Email
                var user = await _userManager.FindByEmailAsync(loginDto.Email.ToLowerInvariant());

                if (user == null)
                {
                    TempData["Error"] = "Invalid Email";
                    return RedirectToAction("Login", "Account");
                }

                if (!await _userManager.CheckPasswordAsync(user, loginDto.Password))
                {
                    TempData["Error"] = "Incorrect Password";
                    return RedirectToAction("Login", "Account");          
                }

                // Check if the user is verified (customize this logic based on your app)
                if (!user.IsVerified)
                {
                    // User is not verified; send a new verification code to their email
                    string otp = GenerateOTP();

                    // Update the user's verification code and expiration time
                    user.VerificationCode = otp;
                    user.VerificationCodeExpiration = DateTime.UtcNow.AddMinutes(5);
                    await _userManager.UpdateAsync(user);

                    // Send verification email
                    var emailHtml = await RenderViewToStringAsync("EmailNot", user);
                    emailHtml = emailHtml.Replace("{{VerificationLink}}", "https://localhost:7137/verify?code=" + user.VerificationCode);

                    bool otpSent = SendEmail(user.Email, "Email Verification", emailHtml);

                    if (!otpSent)
                    {
                        return StatusCode((int)HttpStatusCode.InternalServerError, "Failed to send OTP email. Please try again later.");
                    }

                    TempData["Error"] = "Your account is not verified. We've sent a new verification code to your email.";

                    // Return the "verify" view
                    var verificationDto = new VerificationDto
                    {
                        // Pass any necessary data to the view
                    };

                    return View("Verify", verificationDto);
                }

                // User is verified; generate a JWT token
                var token = GenerateJwtToken(user);

                // Store user info in TempData for the view (customize as needed)
                TempData["UserId"] = user.Id;
                TempData["UserName"] = user.UserName;
                TempData["UserEmail"] = user.Email;

                // If rememberMe is true, set the authentication cookie to be persistent
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = rememberMe,
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
        {
                    
            // Add any claims you need for the user here
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.UserName),
            // Add more claims as needed
        }, CookieAuthenticationDefaults.AuthenticationScheme)), authProperties);

                return RedirectToAction("Index", "Home"); // Redirect to the dashboard or desired page
            }
            catch (Exception ex)
            {
                TempData["Error"] = $"Internal server error: {ex.Message}";
                return RedirectToAction("Login"); // Redirect to the login view with an error message
            }
        }

        // Helper method to render a view to string
        private async Task<string> RenderViewToStringAsync(string viewName, object model)
        {
            var httpContext = new DefaultHttpContext { RequestServices = _serviceProvider };
            var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

            using (var sw = new StringWriter())
            {
                var viewResult = _razorViewEngine.FindView(actionContext, viewName, false);

                if (viewResult.View == null)
                {
                    throw new ArgumentNullException($"{viewName} does not match any available view");
                }

                var viewData = new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    Model = model
                };
                var viewContext = new ViewContext(
                    actionContext,
                    viewResult.View,
                    viewData,
                    new TempDataDictionary(actionContext.HttpContext, _tempDataProvider),
                    sw,
                    new HtmlHelperOptions()
                );

                await viewResult.View.RenderAsync(viewContext);
                return sw.ToString();
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
                expires: DateTime.UtcNow.AddHours(48), // Token expiration time (adjust as needed)
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

                mail.From = new MailAddress("NoReply@CandaceBID.com");
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
