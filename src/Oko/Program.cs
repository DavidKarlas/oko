using Oko;
using Oko.Capture;
using Oko.Http;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Configuration.AddEnvironmentVariables("OKO_");
builder.Services.ConfigureHttpJsonOptions(json => json.SerializerOptions.TypeInfoResolverChain.Insert(0, OkoJson.Default));

OkoOptions options;
try
{
    options = OkoOptions.FromConfiguration(builder.Configuration);
}
catch (OkoConfigurationException exception)
{
    // Refuse to start rather than run with a silently defaulted port or retention policy.
    Console.Error.WriteLine($"oko: {exception.Message}");
    return 78; // EX_CONFIG
}

builder.WebHost.ConfigureKestrel(kestrel =>
{
    // Capture responses are legitimately long-lived and can be idle for minutes on a quiet link.
    // Without this, Kestrel aborts a live stream it mistakes for a stalled client.
    kestrel.Limits.MinResponseDataRate = null;
    kestrel.Limits.MinRequestBodyDataRate = null;
});

builder.Services.AddSingleton(options);
builder.Services.AddSingleton(new OkoStartTime());
builder.Services.AddSingleton<MonotonicClock>();
builder.Services.AddSingleton<IngestStats>();
builder.Services.AddSingleton(_ => new InterfaceTable(options.InterfacesPath));
builder.Services.AddSingleton<CaptureStore>();
builder.Services.AddSingleton<LiveHub>();
builder.Services.AddSingleton(provider => new UdpDropReader(
    options.UdpPort,
    provider.GetRequiredService<ILogger<UdpDropReader>>()));
builder.Services.AddSingleton<TokenAuthenticator>();
builder.Services.AddSingleton<TokenAuthFilter>();
builder.Services.AddSingleton<StatusReporter>();
builder.Services.AddSingleton<PcapngResponseWriter>();
builder.Services.AddSingleton<CaptureEndpoints.CaptureService>();

// Hosted services stop in reverse registration order, so the listener is registered last to make it
// the first to stop. That lets SegmentWriter drain and flush the tail instead of discarding it.
builder.Services.AddHostedService<SegmentWriter>();
builder.Services.AddHostedService<RetentionService>();
builder.Services.AddHostedService<StatsSampler>();
builder.Services.AddHostedService<LiveFlusher>();
builder.Services.AddHostedService<TzspListener>();
builder.Services.AddHostedService<PcapStreamListener>();

var app = builder.Build();

// Unauthenticated on purpose: container health checks must not need a capture token.
app.MapGet("/healthz", () => Results.Text("ok\n", "text/plain"));

app.MapCaptureEndpoints();

await app.RunAsync();
return 0;
