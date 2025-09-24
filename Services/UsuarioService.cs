using System.Security.Cryptography;
using WebApplication1.Exceptions;
using WebApplication1.Interfaces;
using WebApplication1.Models;
using MailKit.Net.Smtp;
using MimeKit;

namespace WebApplication1.Services
{
    public class UsuarioService : IUsuario
    {
        //Simulando um banco de dados em memória
        private static readonly List<UsuarioModel> usuarioList = [];

        // Construtor estático: executa uma vez quando a classe é carregada pra ja carregar um admin padrão
        static UsuarioService()
        {
            if (!usuarioList.Any(u => u.IsAdmin))
            {
                usuarioList.Add(new UsuarioModel
                {
                    Nome = "Admin",
                    Email = "admin@admin.com",
                    Senha = "admin123",
                    IsAdmin = true
                });

            }
        }

        private void EnviarEmailCadastro(string destinatario, string login, string senha)
        {
            var mensagem = new MimeMessage();
            mensagem.From.Add(new MailboxAddress("Sistema", "dixie.torphy@ethereal.email"));
            mensagem.To.Add(new MailboxAddress("", destinatario));
            mensagem.Subject = "Cadastro realizado";
            mensagem.Body = new TextPart("plain")
            {
                Text = $"Login: {login}\nSenha: {senha}"
            };

            using var cliente = new SmtpClient();
            cliente.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            cliente.Authenticate("dixie.torphy@ethereal.email", "rCzNDufdrvUhxKazSm");
            cliente.Send(mensagem);
            cliente.Disconnect(true);
        }

        public UsuarioModel CreateUsuario(UsuarioModel usuario)
        {
            usuario.Senha = GerarHash(usuario.Senha);
            usuario.Email = FormatarEmailRegex(usuario.Email);
            foreach (var user in usuarioList)
            {
                if (user.Nome == usuario.Nome || user.Email == usuario.Email)
                {
                    return null;
                }
            }
            usuarioList.Add(usuario);

            // Envia e-mail para você após cadastro
            EnviarEmailCadastro("dixie.torphy@ethereal.email", usuario.Email, usuario.Senha);

            return usuario;
        }

        public bool DeleteUsuario(string id)
        {
            var usuario = usuarioList.FirstOrDefault(u => u.Id == id);
            if (usuario == null) return false;
            usuarioList.Remove(usuario);
            return true;
        }

        public List<UsuarioModel> GetAllUsuarios()
        {
            return usuarioList;
        }

        public UsuarioModel GetUsuarioById(string id)
        {
            var usuario = usuarioList.FirstOrDefault(u => u.Id == id);
            if (usuario == null) throw new KeyNotFoundException("Usuário não encontrado");
            return usuario;
        }

        public UsuarioModel UpdateUsuario(string id, UsuarioModel usuario)
        {
            var usuarioExistente = usuarioList.FirstOrDefault(u => u.Id == id);
            if (usuarioExistente == null) throw new KeyNotFoundException("Usuário não encontrado");
            usuarioExistente.Nome = usuario.Nome;
            usuarioExistente.Email = usuario.Email;
            usuarioExistente.Senha = GerarHash(usuario.Senha);
            return usuarioExistente;
        }

        private static string GerarHash(string senha)
        {
            using var md5 = MD5.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(senha);
            var hash = md5.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private static string FormatarEmailRegex(string email)
        {
            email = email.Trim().ToLower();
            var regex = new System.Text.RegularExpressions.Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
            if (!regex.IsMatch(email))
                throw new EmailInvalidoException("Email em formato inválido");
            return email;
        }
    }
}
