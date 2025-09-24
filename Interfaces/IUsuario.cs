using WebApplication1.Models;

namespace WebApplication1.Interfaces
{
    public interface IUsuario
    {
        List<UsuarioModel> GetAllUsuarios();
        UsuarioModel GetUsuarioById(string id);
        UsuarioModel CreateUsuario(UsuarioModel usuario);
        UsuarioModel UpdateUsuario(string id, UsuarioModel usuario);
        bool DeleteUsuario(string id);
    }
}
