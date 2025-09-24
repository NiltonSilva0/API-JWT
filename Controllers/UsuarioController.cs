using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.Exceptions;
using WebApplication1.Interfaces;
using WebApplication1.Models;
using System.Security.Claims;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsuarioController : ControllerBase
    {
        private readonly IUsuario _usuarioService;
        public UsuarioController(IUsuario usuarioService)
        {
            _usuarioService = usuarioService;
        }

        [HttpPost("login")]
        public ActionResult Login([FromBody] UsuarioLogin login)
        {
            // Busca usuário pelo email e senha
            var usuario = _usuarioService.GetAllUsuarios()
                .FirstOrDefault(u => u.Email == login.Email && u.Senha == login.Senha);

            if (usuario == null)
                return Unauthorized("Usuário ou senha inválidos.");

            // Gera token JWT
            var key = System.Text.Encoding.ASCII.GetBytes("sua_chave_secreta_aqui-123456789");
            var claims = new[]
            {
                new System.Security.Claims.Claim("id", usuario.Id),
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, usuario.IsAdmin ? "IsAdmin" : "User")
            };
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // Retorna o token
            return Ok(new { Token = tokenString });
        }

        [HttpGet("listar-todos")]
        [Authorize]
        public ActionResult<List<UsuarioModel>> GetAllUsuarios()
        {
            try
            {
                if (!User.IsInRole("IsAdmin"))
                    throw new RoleInvalidaException("Acesso negado. Função inválida.");

                var usuarios = _usuarioService.GetAllUsuarios();
                if (usuarios.Count == 0)
                    return NoContent();

                return Ok(usuarios);
            }
            catch (RoleInvalidaException ex)
            {
                return StatusCode(403, new { erro = ex.Message });
            }
        }

        [HttpGet("lista-por-id{id}")]
        [Authorize()]
        public ActionResult<UsuarioModel> GetUsuarioById(string id)
        {
            if (!User.IsInRole("IsAdmin"))
                throw new RoleInvalidaException("Acesso negado. Função inválida.");
            try 
            {
                var usuario = _usuarioService.GetUsuarioById(id);
                return Ok(usuario);
            }
            catch (KeyNotFoundException)
            {
                return NotFound("Id não encontrado no banco.");
            }
        }

        [HttpPost("criar-registro")]
        [Authorize]
        public ActionResult<UsuarioModel> CreateUsuario([FromBody]UsuarioModel usuario)
        {
            if (!User.IsInRole("IsAdmin"))
                return StatusCode(403, new { erro = "Apenas administradores podem criar usuários." });

            try 
            {
                var novoUsuario = _usuarioService.CreateUsuario(usuario);
                if (novoUsuario == null)
                    return Conflict("Nome ou Email já existente.");
                return CreatedAtAction(nameof(GetUsuarioById), new { id = novoUsuario.Id }, novoUsuario);
            }
            catch (EmailInvalidoException ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPut("atualizar-registro")]
        [Authorize()]
        public ActionResult<UsuarioModel> UpdateUsuario(string id, [FromBody]UsuarioModel usuario)
        {
            if (!User.IsInRole("IsAdmin"))
                throw new RoleInvalidaException("Acesso negado. Função inválida.");
            try 
            {
                var usuarioAtualizado = _usuarioService.UpdateUsuario(id, usuario);
                return Ok(usuarioAtualizado);
            }
            catch (KeyNotFoundException)
            {
                return NotFound("Id não encontrado no banco.");
            }
        }

        [HttpDelete("deletar-registro")]
        [Authorize()]
        public ActionResult DeleteUsuario(string id)
        {
            if (!User.IsInRole("IsAdmin"))
                throw new RoleInvalidaException("Acesso negado. Função inválida.");

            if (_usuarioService.DeleteUsuario(id))
                return Ok("Usuario deletado com sucesso!");
            else
                return NotFound("Usuário não encontrado no banco.");
        }
    }

}
