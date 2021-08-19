using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace WebApiSegura.Controllers
{
  [RoutePrefix("api/customersSN")]
  public class CustomerWithoutAuthorizationController : ApiController
  {
    [HttpGet]
    public IHttpActionResult GetId(int id)
    {
      var customerFake = "customer-fake";
      return Ok(customerFake);
    }

    [HttpGet]
    public IHttpActionResult GetAllCustomer()
    {
      var customersFake = new string[] { "customer 1", "customer 2", "customer 3" };
      return Ok(customersFake);
    }
  }
}
