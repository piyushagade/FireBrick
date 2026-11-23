using FireBrick.Core.Engine;
using FireBrick.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "FireBrickService";
});

builder.Services.AddSingleton<WindowsFirewallManager>();
builder.Services.AddSingleton<LiveConnectionsMonitor>();
builder.Services.AddSingleton<SecurityAuditMonitor>();
builder.Services.AddSingleton<TemporaryRuleManager>();
builder.Services.AddSingleton<TcpConnectionKiller>();
builder.Services.AddSingleton<NetworkProfileMonitor>();
builder.Services.AddSingleton<RuleLockMonitor>();
builder.Services.AddSingleton<BlocklistManager>();
builder.Services.AddSingleton<AutoRuleManager>();
builder.Services.AddSingleton<DnsResolverCache>();
builder.Services.AddSingleton<GeoIpResolverCache>();
builder.Services.AddSingleton<SettingsStore>();
builder.Services.AddHostedService<FireBrickWorker>();

var host = builder.Build();
host.Run();
