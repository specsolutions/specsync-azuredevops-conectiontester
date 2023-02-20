using System;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.VisualStudio.Services.WebApi;
using System.Text;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.TeamFoundation.Core.WebApi;
using Microsoft.VisualStudio.Services.Common;

namespace SpecSync.AzureDevOps.ConnectionTester
{
    static class Program
    {
        public static void Main(string[] args)
        {

            Console.WriteLine("*** SpecSync for Azure DevOps Connection Tester ***");
            Console.WriteLine();

            if (args.Length < 2)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine(
                    "  SpecSync.ConnectionTester.exe <project-url> <pat>");
                Console.WriteLine("OR");
                Console.WriteLine(
                    "  SpecSync.ConnectionTester.exe <project-url> <username> <password>");
                return;
            }

            var projectUrl = args[0];
            var userNameOrPat = args[1];
            var password = args.Length == 2 || args[2].EndsWith(".pfx", StringComparison.InvariantCultureIgnoreCase)
                ? ""
                : args[2];

            ParseAdoProjectUrl(projectUrl, out var collectionUrl, out var projectName);

            Console.WriteLine($"Collection URL: {collectionUrl}");
            Console.WriteLine($"Project Name: {projectName}");
            Console.WriteLine();

            Console.WriteLine("Testing connection with Azure DevOps .NET API...");

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            try
            {
                var vssConnection = CreateVssConnection(new Uri(collectionUrl),
                    new VssBasicCredential(userNameOrPat, password));
                vssConnection.ConnectAsync().Wait();
                vssConnection.GetClient<ProjectHttpClient>().GetProject(projectName).Wait();
                Console.WriteLine("Succeeded!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed!");
                PrintError(ex);
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Testing connection with HttpClient...");
            try
            {
                var handler = new HttpClientHandler();
                var httpClient = new HttpClient(handler);
                httpClient.BaseAddress = new Uri(collectionUrl + "/");
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes(userNameOrPat + ":" + password)));
                var response = httpClient.GetAsync($"_apis/projects/{projectName}?includeHistory=False").Result;
                Console.WriteLine($"  {response.RequestMessage?.RequestUri}");
                Console.WriteLine($"  {(int)response.StatusCode} ({response.StatusCode})");
                if (response.StatusCode != HttpStatusCode.OK)
                    Console.WriteLine("Failed! Wrong HTTP status code.");
                else
                    Console.WriteLine("Succeeded!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed!");
                PrintError(ex);
            }

            Console.WriteLine();
            Console.WriteLine();
        }

        static VssConnection CreateVssConnection(Uri adoCollectionUrl, VssCredentials credentials)
        {
            var vssHttpRequestSettings = VssClientHttpRequestSettings.Default.Clone();
            vssHttpRequestSettings.ServerCertificateValidationCallback = ServerCertificateValidationCallback;
            var httpMessageHandlers = Enumerable.Empty<DelegatingHandler>();

            var innerHandler = new HttpClientHandler();
            var vssHttpMessageHandler = new VssHttpMessageHandler(credentials, vssHttpRequestSettings, innerHandler);
            return new VssConnection(adoCollectionUrl,
                vssHttpMessageHandler,
                httpMessageHandlers);
        }

        static bool ServerCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors errors)
        {
            if (errors == SslPolicyErrors.None)
            {
                Console.WriteLine("  SSL validation passed.");
                return true;
            }

            var hashString = certificate.GetCertHashString();
            Console.WriteLine($"SSL policy error(s) '{errors}' found for certificate thumbprint '{hashString}'.");
            Console.WriteLine("  SSL validation failed. Ignoring...");
            return true;
        }

        static void ParseAdoProjectUrl(string url, out string adoCollectionUrl, out string adoProjectName)
        {
            url = url.TrimEnd('/');
            var lastSlash = url.LastIndexOf('/');
            if (lastSlash < 0)
            {
                throw new InvalidOperationException($"Unable to parse Azure DevOps project URL: {url}");
            }

            adoCollectionUrl = url.Substring(0, lastSlash);
            adoProjectName = url.Substring(lastSlash + 1);
            adoProjectName = WebUtility.UrlDecode(adoProjectName);
        }

        static void PrintError(Exception exception, string indent = "")
        {
            var errorCode = "";
            if (exception is Win32Exception win32Exception)
            {
                errorCode = $" (0x{win32Exception.NativeErrorCode:x8})";
            }

            Console.WriteLine($"{indent}{exception.GetType().FullName}{errorCode}: {exception.Message}");
            if (exception is AggregateException aggregateException)
            {
                foreach (var innerEx in aggregateException.InnerExceptions)
                {
                    PrintError(innerEx, indent + " ---> ");
                }
            }
            else if (exception.InnerException != null)
            {
                PrintError(exception.InnerException, indent + " ---> ");
            }

            //more detailed log:
            //if (indent == "")
            //{
            //    Console.WriteLine();
            //    Console.WriteLine(exception);
            //}
        }
    }
}
