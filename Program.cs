using System.Net;
using System.Net.Http.Headers;
using Microsoft.VisualStudio.Services.WebApi;
using System.Text;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.TeamFoundation.Core.WebApi;
using Microsoft.VisualStudio.Services.Common;

// See https://aka.ms/new-console-template for more information
void ParseAdoProjectUrl(string url, out string collectionUrl, out string projectName){
  url = url.TrimEnd('/');
  var lastSlash = url.LastIndexOf('/');
  if (lastSlash < 0)
  {
      throw new InvalidOperationException($"Unable to parse Azure DevOps project URL: {url}");
  }
  collectionUrl = url.Substring(0, lastSlash);
  projectName = url.Substring(lastSlash + 1);
  projectName = WebUtility.UrlDecode(projectName);
}

VssConnection CreateVssConnection(Uri collectionUrl, VssCredentials credentials)
{
    var vssHttpRequestSettings = VssClientHttpRequestSettings.Default.Clone();
    vssHttpRequestSettings.ServerCertificateValidationCallback = ServerCertificateValidationCallback;

    var httpMessageHandlers = Enumerable.Empty<DelegatingHandler>();

    return new VssConnection(collectionUrl,
        new VssHttpMessageHandler(credentials, vssHttpRequestSettings),
        httpMessageHandlers);
}

bool ServerCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
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



Console.WriteLine("*** SpecSync for Azure DevOps Connection Tester ***");
System.Console.WriteLine();

if (args.Length < 2){
  System.Console.WriteLine("Usage:");
  System.Console.WriteLine("  SpecSync.ConnectionTester.exe <project-url> <pat>");
  System.Console.WriteLine("OR");
  System.Console.WriteLine("  SpecSync.ConnectionTester.exe <project-url> <username> <password>");
  return;
}

var projectUrl = args[0];
var userNameOrPat = args[1];
var password = args.Length == 2 ? "" : args[2];

ParseAdoProjectUrl(projectUrl, out var collectionUrl, out var projectName);

Console.WriteLine($"Collection URL: {collectionUrl}");
Console.WriteLine($"Project Name: {projectName}");
Console.WriteLine();

Console.WriteLine("Testing connection with Azure DevOps .NET API...");
try {
  var vssConnection = CreateVssConnection(new Uri(collectionUrl), new VssBasicCredential(userNameOrPat, password));
  vssConnection.ConnectAsync().Wait();
  vssConnection.GetClient<ProjectHttpClient>().GetProject(projectName).Wait();
  System.Console.WriteLine("Succeeded!");
}
catch(Exception ex){
  System.Console.WriteLine("Failed!");
  System.Console.WriteLine(ex);
}
System.Console.WriteLine();
System.Console.WriteLine();
Console.WriteLine("Testing connection with HttpClient...");
try {
  var httpClient = new HttpClient();
  httpClient.BaseAddress = new Uri(collectionUrl + "/");
  httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(userNameOrPat + ":" + password)));
  var response = httpClient.GetAsync($"_apis/projects/{projectName}?includeHistory=False").Result;
  System.Console.WriteLine($"  {response.RequestMessage?.RequestUri}");
  System.Console.WriteLine($"  {(int)response.StatusCode} ({response.StatusCode})");
  if (response.StatusCode != HttpStatusCode.OK)
    System.Console.WriteLine("Failed! Wrong HTTP status code.");  
  else
    System.Console.WriteLine("Succeeded!");
}
catch(Exception ex){
  System.Console.WriteLine("Failed!");
  System.Console.WriteLine(ex);
}
System.Console.WriteLine();
System.Console.WriteLine();