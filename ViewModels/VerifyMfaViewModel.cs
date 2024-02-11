using System.ComponentModel.DataAnnotations;

namespace BrokenAuthenticationSample.ViewModels
{
    public class VerifyMfaViewModel
    {
        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }

}
