using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.Services.Common;

namespace SpecSync.AzureDevOps.ConnectionTester
{
    class ClientCertificateManager : IVssClientCertificateManager
    {
        public X509Certificate2Collection ClientCertificates { get; } = new();
    }
}