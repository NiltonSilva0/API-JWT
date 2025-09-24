namespace WebApplication1.Exceptions
{
    public class EmailInvalidoException : Exception
    {
        public EmailInvalidoException(string mensagem) : base(mensagem) { }
    }
}
