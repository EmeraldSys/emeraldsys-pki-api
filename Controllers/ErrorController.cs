using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace EmeraldSysPKIBackend.Controllers
{
    [Route("error")]
    [ApiController]
    public class ErrorController : ControllerBase
    {
        [HttpGet("404")]
        public IActionResult Get404()
        {
            return NotFound();
        }
    }
}
