
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Microsoft.AspNet.Identity;
using ADL.Data.EntitiyModel.ATRAKModel;
using System.Security.Claims;

namespace XXX.Web.Services.Attributes {

    /// <summary>
    /// An authorization filter that verifies the request's <see cref="IPrincipal"/>.
    /// </summary>
    /// <remarks>You can declare multiple of these attributes per action. You can also use <see cref="AllowAnonymousAttribute"/>
    /// to disable authorization for a specific action.</remarks>

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
    public class ATRAKAuthorizeAttribute : AuthorizationFilterAttribute {
        private readonly object _typeId = new object();
        /// <summary>
        /// Gets a unique identifier for this <see cref="T:System.Attribute"/>.
        /// </summary>
        /// <returns>The unique identifier for the attribute.</returns>
        public override object TypeId {
            get { return _typeId; }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="methodName"></param>
        /// <returns></returns>
        private List<string> WebMethodRoles(string methodName) {
            List<string> permittedRoles = new List<string>();
            try {
                using (AtrakModel db = new AtrakModel()) {
                    if (db.WebServiceActions.Where(w => w.Method == methodName).Any()) {
                        permittedRoles = db.WebServiceActions.Where(w => w.Method == methodName).Select(x => x.AspNetRoles.Select(y => y.Name)).Single().ToList();
                    }
                    else {
                        WebServiceAction wsa = new WebServiceAction();
                        wsa.Method = methodName;
                        db.WebServiceActions.Add(wsa);
                        db.SaveChanges();
                    }
                }
            }
            catch (Exception ex) {
                logger.Error("Authorization Request: WebMethodRoles() ", ex);
            }
            return permittedRoles;
        }

        /// <summary>
        /// Determines whether access for this particular request is authorized. This method uses the user <see cref="IPrincipal"/>
        /// returned via <see cref="HttpRequestContext.Principal"/>. Authorization is denied if the user is not authenticated,
        /// the user is not in the authorized group of <see cref="Users"/> (if defined), or if the user is not in any of the authorized 
        /// <see cref="Roles"/> (if defined).
        /// </summary>
        /// <param name="actionContext">The context.</param>
        /// <returns><c>true</c> if access is authorized; otherwise <c>false</c>.</returns>
        protected virtual bool IsAuthorized(HttpActionContext actionContext) {
            if (actionContext == null) {
                throw Error.ArgumentNull("actionContext");
            }
            List<string> permittedRoles = WebMethodRoles(actionContext.ActionDescriptor.ControllerDescriptor.ControllerName + "." + actionContext.ActionDescriptor.ActionName);
            IPrincipal user = actionContext.ControllerContext.RequestContext.Principal;

            if (user == null || user.Identity == null || !user.Identity.IsAuthenticated) {
                return false;
            }
            else {
                int userId = 0;
                userId =   user.Identity.GetUserId<int>();
                if(userId != 0) {
                    AtrakModel db = new AtrakModel();
                    var currentRoles = db.AspNetUsers.First(x => x.Id == userId).AspNetRoles.ToList();
                    List<string> userRoles =  db.AspNetUsers.First(x => x.Id == userId).AspNetRoles.Select(x => x.Name).ToList();
                    if (userRoles.Intersect(permittedRoles).Any()) {
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>
        /// Called when an action is being authorized. This method uses the user <see cref="IPrincipal"/>
        /// returned via <see cref="HttpRequestContext.Principal"/>. Authorization is denied if
        /// - the request is not associated with any user.
        /// - the user is not authenticated,
        /// - the user is authenticated but is not in the authorized group of <see cref="Users"/> (if defined), or if the user
        /// is not in any of the authorized <see cref="Roles"/> (if defined).
        /// 
        /// If authorization is denied then this method will invoke <see cref="HandleUnauthorizedRequest(HttpActionContext)"/> to process the unauthorized request.
        /// </summary>
        /// <remarks>You can use <see cref="AllowAnonymousAttribute"/> to cause authorization checks to be skipped for a particular
        /// action or controller.</remarks>
        /// <seealso cref="IsAuthorized(HttpActionContext)" />
        /// <param name="actionContext">The context.</param>
        /// <exception cref="ArgumentNullException">The context parameter is null.</exception>
        public override void OnAuthorization(HttpActionContext actionContext) {
            if (actionContext == null) {
                throw Error.ArgumentNull("actionContext");
            }
            if (SkipAuthorization(actionContext)) {
                return;
            }
            if (!IsAuthorized(actionContext)) {
                HandleUnauthorizedRequest(actionContext);
            }
        }

        /// <summary>
        /// Processes requests that fail authorization. This default implementation creates a new response with the
        /// Unauthorized status code. Override this method to provide your own handling for unauthorized requests.
        /// </summary>
        /// <param name="actionContext">The context.</param>
        protected virtual void HandleUnauthorizedRequest(HttpActionContext actionContext) {
            if (actionContext == null) {
                throw Error.ArgumentNull("actionContext");
            }
            logger.Info("Authorization has been denied for this request.");
            actionContext.Response = actionContext.ControllerContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            actionContext.Response.Headers.WwwAuthenticate.Add(new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer"));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="actionContext"></param>
        /// <returns></returns>
        private static bool SkipAuthorization(HttpActionContext actionContext) {
            Contract.Assert(actionContext != null);
            if (actionContext.ActionDescriptor.GetCustomAttributes<ATRAKAuthorizeAttribute>().Any()) {
                return false;
            }
            else{
                return true;
            }
        }
    }
}
