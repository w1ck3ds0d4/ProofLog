using Microsoft.Extensions.DependencyInjection;

namespace ProofLog;

/// <summary>DI wiring so an app can adopt ProofLog in one line.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>Register a durable, SQLite-backed <see cref="IProofLog"/> as a singleton.
    /// Inject <see cref="IProofLog"/> anywhere and call <c>Append</c>.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="path">SQLite path (created if missing), or <c>":memory:"</c>.</param>
    /// <param name="signingKey">Optional HMAC key (see signing).</param>
    public static IServiceCollection AddProofLog(this IServiceCollection services, string path, byte[]? signingKey = null)
    {
        services.AddSingleton<IProofLog>(_ => new SqliteProofLog(path, signingKey: signingKey));
        return services;
    }

    /// <summary>Register a durable, SQLite-backed <see cref="IProofLog"/> signed with an
    /// explicit signer - use an <see cref="EcdsaProofSigner"/> for asymmetric,
    /// auditor-verifiable signing.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="path">SQLite path (created if missing), or <c>":memory:"</c>.</param>
    /// <param name="signer">The signer to sign and verify every record with.</param>
    public static IServiceCollection AddProofLog(this IServiceCollection services, string path, IProofSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        services.AddSingleton<IProofLog>(_ => new SqliteProofLog(path, signer));
        return services;
    }
}
