using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Web.Http;
using WebApiSegura.Models;
using WebApiSegura.Models.Dto;

namespace WebApiSegura.Controllers
{

  /// <summary>
  /// login controller class for authenticate users
  /// </summary>
  [AllowAnonymous]
  [RoutePrefix("api/login")]
  public class LoginController : ApiController
  {
    [HttpGet]
    [Route("echoping")]
    public IHttpActionResult EchoPing()
    {
      return Ok(true);
    }

    [HttpGet]
    [Route("echouser")]
    public IHttpActionResult EchoUser()
    {
      var identity = Thread.CurrentPrincipal.Identity;
      return Ok($" IPrincipal-user: {identity.Name} - IsAuthenticated: {identity.IsAuthenticated}");
    }

    [HttpPost]
    [Route("authenticate")]
    public IHttpActionResult Authenticate(LoginRequest login)
    {
      if (login == null)
        throw new HttpResponseException(HttpStatusCode.BadRequest);

      //TODO: Validate credentials Correctly, this code is only for demo !!
      bool isCredentialValid = (login.Password == "123456");
      if (isCredentialValid)
      {
        var token = TokenGenerator.GenerateTokenJwt(login.Username);
        return Ok(token);
      }
      else
      {
        return Unauthorized();
      }
    }


    [HttpPost]
    [Route("CreateToken")]
    public IHttpActionResult CreateToken(AuthenticationResult.Request request)
    {
      AuthenticationResult.Response response = new AuthenticationResult.Response();
      if (request == null)
        throw new HttpResponseException(HttpStatusCode.BadRequest);
      if (request.document > 0)
      {
        string unique_name = string.Format("{0}{1}", request.document, request.complement.Trim());
        response = TokenGenerator.GenerateTokenLoginJwt(unique_name);
        return Ok(response);
      }
      else
      {
        return Unauthorized();
      }
    }
  }

}
