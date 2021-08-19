using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApiSegura.Models.Dto
{
  public class AuthenticationResult
  {
    public class Request
    {
      public long document { get; set; }
      public string complement { get; set; }
    }
    public class Response
    {
      public string Token { get; set; }
    }
  }
}