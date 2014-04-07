using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Common.Auth.Models
{
    public abstract class BaseCredential
    {
        [Key]
        public abstract int Id { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string Password { get; set; }

        [Timestamp]
        public byte[] RowVersion { get; set; }
    }
}
