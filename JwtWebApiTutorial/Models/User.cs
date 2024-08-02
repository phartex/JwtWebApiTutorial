namespace JwtWebApiTutorial.Models
{
    public class User
    {
        public string Username { get; set; }   = string.Empty;
        public byte[] PasswordHarsh { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
