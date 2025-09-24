using System;

namespace WebApplication1.Exceptions
{
    public class RoleInvalidaException : Exception
    {
        public RoleInvalidaException() { }

        public RoleInvalidaException(string message) : base(message) { }

        public RoleInvalidaException(string message, Exception inner) : base(message, inner) { }
    }
}
