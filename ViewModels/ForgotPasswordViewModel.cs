using System.ComponentModel.DataAnnotations;

namespace BrokenAuthenticationSample.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }


}
