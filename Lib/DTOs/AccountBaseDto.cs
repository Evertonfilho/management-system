﻿using System.ComponentModel.DataAnnotations;

namespace Lib.DTOs
{
    public class AccountBaseDto
    {
        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        [Required]
        public string? Email { get; set; }

        [DataType(DataType.Password)]
        [Required]
        public string? Password { get; set; }
    }
}