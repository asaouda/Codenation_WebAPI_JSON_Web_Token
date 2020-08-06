using Codenation.Challenge.Models;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using System.Linq;
using System.Threading.Tasks;
 
namespace Codenation.Challenge.Services
{
    public class PasswordValidatorService: IResourceOwnerPasswordValidator
    {
        private CodenationContext codenationContext;

        public PasswordValidatorService(CodenationContext dbContext)
        {
            this.codenationContext = dbContext;
        }

        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
        {

            var user = codenationContext.Users.FirstOrDefault(x => x.Email == context.UserName);

            // verificar a senha
            if (user != null && user.Password.TrimEnd() == context.Password)
            {
                // retornar objeto tipo GrantValidationResult com sub, auth e claims
                context.Result = new GrantValidationResult(
                    subject: user.Id.ToString(),
                    authenticationMethod: "custom",
                    claims: UserProfileService.GetUserClaims(user)
                );
                return Task.CompletedTask;
            }
            else
            {
                context.Result = new GrantValidationResult(
                    TokenRequestErrors.InvalidGrant, "Usuário ou senha inválidos");

                return Task.FromResult(context.Result);
            }
            context.Result = new GrantValidationResult(
                TokenRequestErrors.InvalidGrant, "Invalid username or password");
            return Task.CompletedTask;
        }
     
    }
}