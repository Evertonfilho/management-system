
using System.ComponentModel.DataAnnotations;

namespace Lib.DTOs
{
    public class RegisterDto : AccountBaseDto
    {
        [Required]
        [MinLength(5)]
        [MaxLength(100)]
        public string? Fullname { get; set; }

        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        [Required]
        public string? ConfirmPassword { get; set; }

    }
}
