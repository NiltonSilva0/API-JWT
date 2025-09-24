using System.Text.Json.Serialization;

namespace WebApplication1.Models
{
    public class UsuarioModel
    {
        [JsonIgnore]
        private Guid _Id { get; } = Guid.NewGuid();
        public string Id { get { return _Id.ToString(); } }
        public string Nome { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Senha { get; set; } = string.Empty;
        public bool IsAdmin { get; set; } = false;
    }
}
