using System.ComponentModel;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.VisualStudio.Services.WebApi;
using System.Text;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.TeamFoundation.Core.WebApi;
using Microsoft.VisualStudio.Services.Common;

void PrintError(Exception exception, string indent = "")
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

    //if (indent == "")
    //{
    //    Console.WriteLine();
    //    Console.WriteLine(exception);
    //}
}

X509Certificate LoadClientCertificate(string filePath)
{
    try
    {
        return new X509Certificate2(filePath);
    }
    catch (Exception)
    {
        Console.Write("Please specify password for client certificate or leave empty if no password required: ");
        var certPassword = Console.ReadLine();
        return new X509Certificate2(filePath, certPassword);
    }
}

void ParseAdoProjectUrl(string url, out string adoCollectionUrl, out string adoProjectName)
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

VssConnection CreateVssConnection(Uri adoCollectionUrl, VssCredentials credentials, X509Certificate? clientCertificate)
{
    var vssHttpRequestSettings = VssClientHttpRequestSettings.Default.Clone();
    vssHttpRequestSettings.ServerCertificateValidationCallback = ServerCertificateValidationCallback;
    if (clientCertificate != null)
    {
        vssHttpRequestSettings.ClientCertificateManager = new ClientCertificateManager();
        vssHttpRequestSettings.ClientCertificateManager.ClientCertificates.Add(clientCertificate);
    }

    var httpMessageHandlers = Enumerable.Empty<DelegatingHandler>();

    return new VssConnection(adoCollectionUrl,
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
Console.WriteLine();

if (args.Length < 2)
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  SpecSync.ConnectionTester.exe <project-url> <pat> [<client-certificate-file>.pfx]");
    Console.WriteLine("OR");
    Console.WriteLine("  SpecSync.ConnectionTester.exe <project-url> <username> <password> [<client-certificate-file>.pfx]");
    return;
}

var projectUrl = args[0];
var userNameOrPat = args[1];
var password = args.Length == 2 || args[2].EndsWith(".pfx", StringComparison.InvariantCultureIgnoreCase) ? "" : args[2];
var clientCertificateFile = args.Last().EndsWith(".pfx", StringComparison.InvariantCultureIgnoreCase) ? args.Last() : null;

ParseAdoProjectUrl(projectUrl, out var collectionUrl, out var projectName);

if (clientCertificateFile != null)
{
    clientCertificateFile = Path.GetFullPath(clientCertificateFile);
    if (!File.Exists(clientCertificateFile))
        throw new InvalidOperationException($"Client certificate file does not exist: {clientCertificateFile}");
}

Console.WriteLine($"Collection URL: {collectionUrl}");
Console.WriteLine($"Project Name: {projectName}");
if (clientCertificateFile != null)
    Console.WriteLine($"Client certificate file: {clientCertificateFile}");
Console.WriteLine();

var clientCertificate = clientCertificateFile != null ? LoadClientCertificate(clientCertificateFile) : null;

Console.WriteLine("Testing connection with Azure DevOps .NET API...");

ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

try
{
    var vssConnection = CreateVssConnection(new Uri(collectionUrl), new VssBasicCredential(userNameOrPat, password), clientCertificate);
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
    if (clientCertificate != null)
        handler.ClientCertificates.Add(clientCertificate);

    var httpClient = new HttpClient(handler);
    httpClient.BaseAddress = new Uri(collectionUrl + "/");
    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(userNameOrPat + ":" + password)));
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
