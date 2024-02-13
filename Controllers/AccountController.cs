using BrokenAuthenticationSample.Contract.Email;
using BrokenAuthenticationSample.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace BrokenAuthenticationSample.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IEmailSender _emailSender;

        public AccountController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ILogger<AccountController> logger,
            IEmailSender emailSender)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
        }

        // GET: /Account/Login
        #region Login / Logout

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");
                return RedirectToLocal(returnUrl);
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                return RedirectToAction(nameof(Lockout));
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        #endregion

        #region Registration

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = new IdentityUser { UserName = model.Email, Email = model.Email, TwoFactorEnabled = true };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Confirm your email", $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                // Redirect to the success message view
                return View("RegistrationSuccess");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        #endregion      

        #region Email Confirmation

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, code);
            return result.Succeeded ? View("ConfirmEmailConfirmation") : View("Error");
        }

        #endregion

        #region Password Reset

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                // Only send the email if the user exists and is confirmed.
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { code = code }, protocol: HttpContext.Request.Scheme);

                    await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                        $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                }

                // Regardless of user existence or confirmation status, redirect to a generic confirmation view.
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            // If we got this far, something failed, redisplay form.
            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            // Ensure the code is passed to the view for submission with the form
            return code == null ? View("Error") : View(new ResetPasswordViewModel { Code = code });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {

                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        #endregion

        #region Verify Mfa Code
        public async Task<IActionResult> VerifyMfaCode(string returnUrl = null, bool rememberMe = false)
        {
            // View model to capture the MFA code
            return View(new VerifyMfaViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyMfaCode(VerifyMfaViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var result = await _signInManager.TwoFactorSignInAsync(TokenOptions.DefaultEmailProvider, model.Code, model.RememberMe, rememberClient: false);
            if (result.Succeeded)
            {
                return RedirectToLocal(model.ReturnUrl);
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid code.");
                return View(model);
            }
        }
        #endregion

        #region Helpers

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        public IActionResult Lockout()
        {
            return View();
        }

        #endregion




    }

}
