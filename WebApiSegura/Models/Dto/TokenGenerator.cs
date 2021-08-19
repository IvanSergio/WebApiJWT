using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Drawing;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Net;

namespace WebApiSegura.Models.Dto
{
  /// <summary>
  /// JWT Token generator class using "secret-key"
  /// more info: https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
  /// </summary>
  internal static class TokenGenerator
  {

    public static readonly string ClaimsDocument = "Document";
    public static readonly string ClaimsComplement = "Complement";
    public static readonly string ClaimsToken = "Token";

    public static string GenerateTokenJwt(string username)
    {
      // appsetting for Token JWT
      var secretKey = ConfigurationManager.AppSettings["JWT_SECRET_KEY"];
      var audienceToken = ConfigurationManager.AppSettings["JWT_AUDIENCE_TOKEN"];
      var issuerToken = ConfigurationManager.AppSettings["JWT_ISSUER_TOKEN"];
      var expireTime = ConfigurationManager.AppSettings["JWT_EXPIRE_MINUTES"];

      var securityKey = new SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(secretKey));
      var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

      // create a claimsIdentity
      ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) });

      // create token to the user
      var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
      var jwtSecurityToken = tokenHandler.CreateJwtSecurityToken(
          audience: audienceToken,
          issuer: issuerToken,
          subject: claimsIdentity,
          notBefore: DateTime.UtcNow,
          expires: DateTime.UtcNow.AddMinutes(Convert.ToInt32(expireTime)),
          signingCredentials: signingCredentials);

      var jwtTokenString = tokenHandler.WriteToken(jwtSecurityToken);
      return jwtTokenString;
    }

    /// <summary>
    /// Metodo que genera Token
    /// </summary>
    /// <param name="unique_name"></param>
    /// <returns></returns>
    public static AuthenticationResult.Response GenerateTokenLoginJwt(string unique_name)
    {
      AuthenticationResult.Response response = new AuthenticationResult.Response();
      try
      {
        // appsetting for Token JWT
        var secretKey = ConfigurationManager.AppSettings["JWT_SECRET_KEY"];
        var audienceToken = ConfigurationManager.AppSettings["JWT_AUDIENCE_TOKEN"];
        var issuerToken = ConfigurationManager.AppSettings["JWT_ISSUER_TOKEN"];
        var expireTime = ConfigurationManager.AppSettings["JWT_EXPIRE_MINUTES"];

        var securityKey = new SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(secretKey));
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

        // create a claimsIdentity
        //ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, unique_name) });
        ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[] { new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), new Claim("Document", "8264274"), new Claim("Complement", "") });



        //var claimsIdentity = new[] {
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        new Claim("Document", "8264274"),
        //        new Claim("Complement", "")
        //    };

        // create token to the user
        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtSecurityToken = tokenHandler.CreateJwtSecurityToken(
            //audience: audienceToken,
            //issuer: issuerToken,
            subject: claimsIdentity,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(Convert.ToInt32(expireTime)),
            signingCredentials: signingCredentials);

        var jwtTokenString = tokenHandler.WriteToken(jwtSecurityToken);
        response.Token = jwtTokenString;
      }
      catch (Exception ex)
      {
        throw;
      }
      return response;
    }

    /// <summary>
    /// Metodo que obtiene la informacion del Token
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public static AuthenticationResult.Request GetTokenData(string token)
    {
      var secretKey = ConfigurationManager.AppSettings["JWT_SECRET_KEY"];
      var key = Encoding.ASCII.GetBytes(secretKey);
      var handler = new JwtSecurityTokenHandler();
      var validations = new TokenValidationParameters
      {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
      };
      var claims = handler.ValidateToken(token, validations, out var tokenSecure);
      if (claims != null)
        return new AuthenticationResult.Request
        {
          document = Convert.ToInt64(claims.Claims.ToList().Find(x => x.Type == ClaimsDocument).Value),
          complement = Convert.ToString(claims.Claims.ToList().Find(x => x.Type == ClaimsComplement).Value)
        };
      else
        return new AuthenticationResult.Request { document = 0, complement = string.Empty };
    }

  }
}