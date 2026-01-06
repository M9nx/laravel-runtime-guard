<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use M9nx\RuntimeGuard\Advanced\HoneytokenManager;
use M9nx\RuntimeGuard\Advanced\RuntimePolicyEngine;
use M9nx\RuntimeGuard\Advanced\ThreatIntelFeed;
use M9nx\RuntimeGuard\Advanced\WafRuleExporter;
use M9nx\RuntimeGuard\Analytics\AttackFingerprinter;
use M9nx\RuntimeGuard\Analytics\ComplianceReporter;
use M9nx\RuntimeGuard\Analytics\GeoIpCorrelator;
use M9nx\RuntimeGuard\Analytics\StixExporter;
use M9nx\RuntimeGuard\Analytics\TrendAnalyzer;
use M9nx\RuntimeGuard\Analytics\AttackChainReconstructor;
use M9nx\RuntimeGuard\Analytics\RiskScoringEngine;
use M9nx\RuntimeGuard\DevTools\GuardProfiler;
use M9nx\RuntimeGuard\DevTools\RuleBuilder;
use M9nx\RuntimeGuard\DevTools\SecurityPlayground;
use M9nx\RuntimeGuard\DevTools\TestDataGenerator;
use M9nx\RuntimeGuard\ML\AdaptiveThresholdManager;
use M9nx\RuntimeGuard\ML\MLAnomalyDetector;
use M9nx\RuntimeGuard\ML\PatternLearningEngine;
use M9nx\RuntimeGuard\ML\ThreatClassifier;
use M9nx\RuntimeGuard\MultiTenant\CrossTenantIntelligence;
use M9nx\RuntimeGuard\MultiTenant\TenantIsolationManager;
use M9nx\RuntimeGuard\MultiTenant\TenantQuotaManager;
use M9nx\RuntimeGuard\MultiTenant\TenantRuleEngine;
use M9nx\RuntimeGuard\Observability\AlertCorrelator;
use M9nx\RuntimeGuard\Observability\RealTimeMetricsCollector;
use M9nx\RuntimeGuard\Observability\SecurityScorecard;
use M9nx\RuntimeGuard\Observability\ThreatHeatmap;
use M9nx\RuntimeGuard\Optimizer\AsyncGuardExecutor;
use M9nx\RuntimeGuard\Optimizer\GuardFusionOptimizer;
use M9nx\RuntimeGuard\Optimizer\IncrementalInspector;
use M9nx\RuntimeGuard\Optimizer\ResourcePoolManager;
use M9nx\RuntimeGuard\Console\Commands\ListGuardsCommand;
use M9nx\RuntimeGuard\Console\Commands\MakeGuardCommand;
use M9nx\RuntimeGuard\Console\Commands\SecurityAuditCommand;
use M9nx\RuntimeGuard\Console\Commands\StatusCommand;
use M9nx\RuntimeGuard\Console\Commands\TestGuardCommand;
use M9nx\RuntimeGuard\Console\Commands\ToggleGuardCommand;
use M9nx\RuntimeGuard\Contracts\GuardManagerInterface;
use M9nx\RuntimeGuard\Contracts\ReporterInterface;
use M9nx\RuntimeGuard\Correlation\CorrelationEngine;
use M9nx\RuntimeGuard\Correlation\ProgressiveEnforcement;
use M9nx\RuntimeGuard\Debug\DebugExplainer;
use M9nx\RuntimeGuard\FeatureFlags\FeatureFlagManager;
use M9nx\RuntimeGuard\Http\Controllers\HealthCheckController;
use M9nx\RuntimeGuard\Http\Middleware\RuntimeGuardMiddleware;
use M9nx\RuntimeGuard\Integrations\OpenApiValidator;
use M9nx\RuntimeGuard\Integrations\PulseIntegration;
use M9nx\RuntimeGuard\Integrations\SiemConnector;
use M9nx\RuntimeGuard\Integrations\TelescopeIntegration;
use M9nx\RuntimeGuard\Notifications\WebhookDispatcher;
use M9nx\RuntimeGuard\Performance\BloomFilter;
use M9nx\RuntimeGuard\Performance\JitWarmer;
use M9nx\RuntimeGuard\Performance\LazyGuardResolver;
use M9nx\RuntimeGuard\Performance\SharedMemoryStore;
use M9nx\RuntimeGuard\Performance\StreamingInspector;
use M9nx\RuntimeGuard\Plugins\PluginManager;
use M9nx\RuntimeGuard\Profiles\ProfileResolver;
use M9nx\RuntimeGuard\Reporters\AsyncReporter;
use M9nx\RuntimeGuard\Reporters\DatabaseReporter;
use M9nx\RuntimeGuard\Reporters\LogReporter;
use M9nx\RuntimeGuard\Resilience\CircuitBreaker;
use M9nx\RuntimeGuard\Resilience\LoadShedder;
use M9nx\RuntimeGuard\Support\RequestFingerprint;
use M9nx\RuntimeGuard\Support\RingBuffer;
use M9nx\RuntimeGuard\Testing\RuntimeGuardFake;

class RuntimeGuardServiceProvider extends ServiceProvider
{
    /**
     * Artisan commands to register.
     *
     * @var array<class-string>
     */
    protected array $commands = [
        ListGuardsCommand::class,
        TestGuardCommand::class,
        StatusCommand::class,
        ToggleGuardCommand::class,
        MakeGuardCommand::class,
        SecurityAuditCommand::class,
    ];

    /**
     * Register package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/runtime-guard.php',
            'runtime-guard'
        );

        $this->registerGuardManager();
        $this->registerReporters();
        $this->registerCorrelation();
        $this->registerFeatureFlags();
        $this->registerProfiles();
        $this->registerTestingSupport();
        $this->registerPerformance();
        $this->registerResilience();
        $this->registerIntegrations();
        $this->registerAnalytics();
        $this->registerNotifications();
        $this->registerPlugins();
        $this->registerDebug();
        $this->registerV4Components();
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->publishConfig();
        $this->publishMigrations();
        $this->publishStubs();
        $this->registerCommands();
        $this->registerMiddleware();
        $this->registerGuards();
        $this->registerHealthCheckRoute();
        $this->bootManager();
        $this->bootIntegrations();
    }

    /**
     * Register the guard manager singleton.
     */
    protected function registerGuardManager(): void
    {
        $this->app->singleton(GuardManagerInterface::class, function ($app) {
            return new GuardManager($app);
        });

        $this->app->alias(GuardManagerInterface::class, 'runtime-guard');
        $this->app->alias(GuardManagerInterface::class, GuardManager::class);
    }

    /**
     * Boot the guard manager with configuration.
     */
    protected function bootManager(): void
    {
        if (! $this->app['config']->get('runtime-guard.enabled', true)) {
            return;
        }

        $manager = $this->app->make(GuardManagerInterface::class);

        if ($manager instanceof GuardManager) {
            $config = $this->app['config']->get('runtime-guard', []);
            $manager->boot($config);

            // Register reporters with manager
            $this->registerManagerReporters($manager);
        }
    }

    /**
     * Register reporters with the guard manager.
     */
    protected function registerManagerReporters(GuardManager $manager): void
    {
        $reportersConfig = $this->app['config']->get('runtime-guard.reporters', []);

        // Log reporter
        if ($reportersConfig['log']['enabled'] ?? true) {
            $manager->registerReporter($this->app->make(LogReporter::class));
        }

        // Database reporter
        if ($reportersConfig['database']['enabled'] ?? false) {
            $manager->registerReporter($this->app->make(DatabaseReporter::class));
        }

        // Async reporter
        if ($reportersConfig['async']['enabled'] ?? false) {
            $manager->registerReporter($this->app->make(AsyncReporter::class));
        }
    }

    /**
     * Register configured guards.
     */
    protected function registerGuards(): void
    {
        if (! $this->app['config']->get('runtime-guard.enabled', true)) {
            return;
        }

        $manager = $this->app->make(GuardManagerInterface::class);
        $guards = $this->app['config']->get('runtime-guard.guards', []);

        foreach ($guards as $name => $config) {
            if (! isset($config['class'])) {
                continue;
            }

            // Bind the guard with its configuration
            $this->app->when($config['class'])
                ->needs('$config')
                ->give(fn () => array_merge(['name' => $name], $config));

            $manager->registerClass($config['class']);
        }
    }

    /**
     * Register configured reporters.
     */
    protected function registerReporters(): void
    {
        // Log reporter
        $this->app->singleton(LogReporter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.reporters.log', []);

            return new LogReporter($app['log'], $config);
        });

        // Database reporter
        $this->app->singleton(DatabaseReporter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.reporters.database', []);

            return new DatabaseReporter($app['db'], $config);
        });

        // Async reporter
        $this->app->singleton(AsyncReporter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.reporters.async', []);
            $innerReporter = $app->make(LogReporter::class);

            return new AsyncReporter($innerReporter, $config);
        });

        $this->app->bind(ReporterInterface::class, LogReporter::class);
    }

    /**
     * Register correlation engine.
     */
    protected function registerCorrelation(): void
    {
        $this->app->singleton(CorrelationEngine::class, function ($app) {
            $config = $app['config']->get('runtime-guard.correlation', []);

            return CorrelationEngine::fromConfig($config);
        });

        $this->app->singleton(ProgressiveEnforcement::class, function ($app) {
            $config = $app['config']->get('runtime-guard.progressive', []);

            return ProgressiveEnforcement::fromConfig($config);
        });
    }

    /**
     * Register feature flag manager.
     */
    protected function registerFeatureFlags(): void
    {
        $this->app->singleton(FeatureFlagManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.feature_flags', []);

            return FeatureFlagManager::fromConfig(
                $config,
                $app->bound('cache') ? $app->make('cache') : null
            );
        });
    }

    /**
     * Register profile resolver.
     */
    protected function registerProfiles(): void
    {
        $this->app->singleton(ProfileResolver::class, function ($app) {
            $config = $app['config']->get('runtime-guard', []);

            return ProfileResolver::fromConfig($config);
        });
    }

    /**
     * Register testing support.
     */
    protected function registerTestingSupport(): void
    {
        $this->app->bind(RuntimeGuardFake::class, function () {
            return new RuntimeGuardFake();
        });
    }

    /**
     * Register artisan commands.
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands($this->commands);
        }
    }

    /**
     * Register middleware.
     */
    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        // Register as route middleware alias
        $router->aliasMiddleware('runtime-guard', RuntimeGuardMiddleware::class);

        // Optionally add to web middleware group
        if ($this->app['config']->get('runtime-guard.middleware.auto_register', false)) {
            /** @var Kernel $kernel */
            $kernel = $this->app->make(Kernel::class);
            $kernel->appendMiddlewareToGroup('web', RuntimeGuardMiddleware::class);
        }
    }

    /**
     * Publish the configuration file.
     */
    protected function publishConfig(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/runtime-guard.php' => config_path('runtime-guard.php'),
            ], 'runtime-guard-config');
        }
    }

    /**
     * Publish database migrations.
     */
    protected function publishMigrations(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'runtime-guard-migrations');

            // Auto-load migrations if database reporter is enabled
            if ($this->app['config']->get('runtime-guard.reporters.database.enabled', false)) {
                $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
            }
        }
    }

    /**
     * Publish stub files for guard generator.
     */
    protected function publishStubs(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../stubs' => base_path('stubs/runtime-guard'),
            ], 'runtime-guard-stubs');
        }
    }

    /**
     * Register performance components.
     */
    protected function registerPerformance(): void
    {
        // Bloom Filter
        $this->app->singleton(BloomFilter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.performance.bloom_filter', []);
            
            return new BloomFilter(
                $config['size'] ?? 10000,
                $config['hash_count'] ?? 3
            );
        });

        // JIT Warmer
        $this->app->singleton(JitWarmer::class, function ($app) {
            $config = $app['config']->get('runtime-guard.performance.jit_warming', []);
            $cacheStore = $app->bound('cache') ? $app['cache']->store() : null;
            
            return new JitWarmer($cacheStore);
        });

        // Lazy Guard Resolver
        $this->app->singleton(LazyGuardResolver::class, function ($app) {
            return new LazyGuardResolver($app);
        });

        // Streaming Inspector
        $this->app->singleton(StreamingInspector::class, function ($app) {
            $config = $app['config']->get('runtime-guard.performance.streaming', []);
            
            return new StreamingInspector(
                $config['chunk_size'] ?? 8192,
                $config['overlap'] ?? 256
            );
        });

        // Shared Memory Store
        $this->app->singleton(SharedMemoryStore::class, function ($app) {
            $config = $app['config']->get('runtime-guard.performance.shared_memory', []);
            
            return new SharedMemoryStore(
                $config['driver'] ?? 'array',
                $config
            );
        });

        // Request Fingerprint
        $this->app->singleton(RequestFingerprint::class, function ($app) {
            return new RequestFingerprint('sha256');
        });

        // Ring Buffer
        $this->app->singleton(RingBuffer::class, function ($app) {
            return new RingBuffer(1000);
        });
    }

    /**
     * Register resilience components (v3.0).
     */
    protected function registerResilience(): void
    {
        // Circuit Breaker
        $this->app->singleton(CircuitBreaker::class, function ($app) {
            $config = $app['config']->get('runtime-guard.resilience.circuit_breaker', []);
            $cacheStore = $app->bound('cache') ? $app['cache']->store() : null;
            
            return new CircuitBreaker($cacheStore, $config);
        });

        // Load Shedder
        $this->app->singleton(LoadShedder::class, function ($app) {
            $config = $app['config']->get('runtime-guard.resilience.load_shedding', []);
            
            return new LoadShedder($config);
        });
    }

    /**
     * Register integration components.
     */
    protected function registerIntegrations(): void
    {
        // Telescope Integration
        $this->app->singleton(TelescopeIntegration::class, function ($app) {
            $config = $app['config']->get('runtime-guard.integrations.telescope', []);
            
            return new TelescopeIntegration($config);
        });

        // Pulse Integration
        $this->app->singleton(PulseIntegration::class, function ($app) {
            $config = $app['config']->get('runtime-guard.integrations.pulse', []);
            
            return new PulseIntegration($config);
        });

        // OpenAPI Validator
        $this->app->singleton(OpenApiValidator::class, function ($app) {
            $config = $app['config']->get('runtime-guard.integrations.openapi', []);
            $specPath = $config['spec_path'] ?? null;
            
            if ($specPath && file_exists($specPath)) {
                return OpenApiValidator::fromFile($specPath);
            }
            
            return new OpenApiValidator([]);
        });

        // SIEM Connector (v3.0)
        $this->app->singleton(SiemConnector::class, function ($app) {
            $config = $app['config']->get('runtime-guard.notifications.siem', []);
            
            return new SiemConnector($config);
        });
    }

    /**
     * Register analytics components.
     */
    protected function registerAnalytics(): void
    {
        // Attack Fingerprinter
        $this->app->singleton(AttackFingerprinter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.analytics.fingerprinting', []);
            $cacheStore = $app->bound('cache') ? $app['cache']->store() : null;
            
            return new AttackFingerprinter($cacheStore, $config);
        });

        // STIX Exporter
        $this->app->singleton(StixExporter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.analytics.stix', []);
            
            return new StixExporter($config);
        });

        // Geo-IP Correlator
        $this->app->singleton(GeoIpCorrelator::class, function ($app) {
            $config = $app['config']->get('runtime-guard.analytics.geo_ip', []);
            $cacheStore = $app->bound('cache') ? $app['cache']->store() : null;
            
            return new GeoIpCorrelator($cacheStore, $config);
        });

        // Trend Analyzer
        $this->app->singleton(TrendAnalyzer::class, function ($app) {
            $config = $app['config']->get('runtime-guard.analytics.trends', []);
            $cacheStore = $app->bound('cache') ? $app['cache']->store() : null;
            
            return new TrendAnalyzer($cacheStore, $config);
        });

        // Compliance Reporter
        $this->app->singleton(ComplianceReporter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.analytics.compliance', []);
            
            return new ComplianceReporter($config);
        });

        // Attack Chain Reconstructor (v3.0)
        $this->app->singleton(AttackChainReconstructor::class, function ($app) {
            $cacheStore = $app->bound('cache') ? $app['cache']->store() : null;
            
            return new AttackChainReconstructor($cacheStore);
        });

        // Risk Scoring Engine (v3.0)
        $this->app->singleton(RiskScoringEngine::class, function ($app) {
            $config = $app['config']->get('runtime-guard.risk_scoring', []);
            
            return new RiskScoringEngine($config);
        });
    }

    /**
     * Register notification components (v3.0).
     */
    protected function registerNotifications(): void
    {
        $this->app->singleton(WebhookDispatcher::class, function ($app) {
            $config = $app['config']->get('runtime-guard.notifications.webhooks', []);
            
            return new WebhookDispatcher($config);
        });
    }

    /**
     * Register plugin system (v3.0).
     */
    protected function registerPlugins(): void
    {
        $this->app->singleton(PluginManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.plugins', []);
            
            return PluginManager::fromConfig($config)->discover();
        });
    }

    /**
     * Register debug components.
     */
    protected function registerDebug(): void
    {
        $this->app->singleton(DebugExplainer::class, function ($app) {
            $config = $app['config']->get('runtime-guard.debug', []);
            $logger = $app['log'];
            
            return new DebugExplainer($logger, $config);
        });
    }

    /**
     * Register health check route.
     */
    protected function registerHealthCheckRoute(): void
    {
        $config = $this->app['config']->get('runtime-guard.health_check', []);
        
        if (! ($config['enabled'] ?? false)) {
            return;
        }

        $path = $config['path'] ?? '/runtime-guard/health';
        $middleware = $config['middleware'] ?? [];

        Route::middleware($middleware)
            ->prefix(trim($path, '/'))
            ->group(function () {
                Route::get('/', [HealthCheckController::class, 'index']);
                Route::get('/detailed', [HealthCheckController::class, 'detailed']);
            });
    }

    /**
     * Boot integration services.
     */
    protected function bootIntegrations(): void
    {
        $config = $this->app['config']->get('runtime-guard.integrations', []);

        // Boot Telescope integration
        if (($config['telescope']['enabled'] ?? false) && class_exists(\Laravel\Telescope\Telescope::class)) {
            $this->app->make(TelescopeIntegration::class)->boot();
        }

        // Boot Pulse integration
        if (($config['pulse']['enabled'] ?? false) && class_exists(\Laravel\Pulse\Pulse::class)) {
            $this->app->make(PulseIntegration::class)->boot();
        }

        // Boot Debug Explainer in debug mode
        if ($this->app['config']->get('runtime-guard.debug.enabled', false)) {
            $this->bootDebugMode();
        }
    }

    /**
     * Boot debug mode features.
     */
    protected function bootDebugMode(): void
    {
        $debugger = $this->app->make(DebugExplainer::class);
        $manager = $this->app->make(GuardManagerInterface::class);

        // Register callbacks for debug logging
        if ($manager instanceof GuardManager) {
            $manager->beforeInspection(function ($guard, $input, $context) use ($debugger) {
                $debugger->beforeInspection($guard, $input, $context);
            });

            $manager->afterInspection(function ($guard, $result, $duration) use ($debugger) {
                $debugger->afterInspection($guard, $result, $duration);
            });

            // Wire callbacks to pipeline
            $pipeline = $manager->getPipeline();
            if ($pipeline) {
                $pipeline->setBeforeCallback(function ($guard, $input, $context) use ($manager) {
                    $manager->fireBeforeInspection($guard, $input, $context);
                });
                $pipeline->setAfterCallback(function ($guard, $result, $duration) use ($manager) {
                    $manager->fireAfterInspection($guard, $result, $duration);
                });
            }
        }
    }

    /**
     * Register v4.0 Ultimate Edition components.
     */
    protected function registerV4Components(): void
    {
        $this->registerV4Guards();
        $this->registerV4ML();
        $this->registerV4Performance();
        $this->registerV4DevTools();
        $this->registerV4MultiTenant();
        $this->registerV4Observability();
        $this->registerV4Advanced();
    }

    /**
     * Register v4.0 security guards.
     */
    protected function registerV4Guards(): void
    {
        // BehavioralFingerprintGuard
        $this->app->singleton(\M9nx\RuntimeGuard\Guards\BehavioralFingerprintGuard::class, function ($app) {
            $config = $app['config']->get('runtime-guard.guards.behavioral-fingerprint', []);
            return new \M9nx\RuntimeGuard\Guards\BehavioralFingerprintGuard($config);
        });

        // PayloadObfuscationGuard
        $this->app->singleton(\M9nx\RuntimeGuard\Guards\PayloadObfuscationGuard::class, function ($app) {
            $config = $app['config']->get('runtime-guard.guards.payload-obfuscation', []);
            return new \M9nx\RuntimeGuard\Guards\PayloadObfuscationGuard($config);
        });

        // ApiAbuseGuard
        $this->app->singleton(\M9nx\RuntimeGuard\Guards\ApiAbuseGuard::class, function ($app) {
            $config = $app['config']->get('runtime-guard.guards.api-abuse', []);
            return new \M9nx\RuntimeGuard\Guards\ApiAbuseGuard($config);
        });

        // PrototypePollutionGuard
        $this->app->singleton(\M9nx\RuntimeGuard\Guards\PrototypePollutionGuard::class, function ($app) {
            $config = $app['config']->get('runtime-guard.guards.prototype-pollution', []);
            return new \M9nx\RuntimeGuard\Guards\PrototypePollutionGuard($config);
        });
    }

    /**
     * Register v4.0 ML/AI components.
     */
    protected function registerV4ML(): void
    {
        // ML Anomaly Detector
        $this->app->singleton(MLAnomalyDetector::class, function ($app) {
            $config = $app['config']->get('runtime-guard.ml.anomaly_detector', []);
            return new MLAnomalyDetector($config);
        });

        // Pattern Learning Engine
        $this->app->singleton(PatternLearningEngine::class, function ($app) {
            $config = $app['config']->get('runtime-guard.ml.pattern_learning', []);
            return new PatternLearningEngine($config);
        });

        // Threat Classifier
        $this->app->singleton(ThreatClassifier::class, function ($app) {
            $config = $app['config']->get('runtime-guard.ml.threat_classifier', []);
            return new ThreatClassifier($config);
        });

        // Adaptive Threshold Manager
        $this->app->singleton(AdaptiveThresholdManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.ml.adaptive_threshold', []);
            return new AdaptiveThresholdManager($config);
        });
    }

    /**
     * Register v4.0 performance optimizers.
     */
    protected function registerV4Performance(): void
    {
        // Guard Fusion Optimizer
        $this->app->singleton(GuardFusionOptimizer::class, function ($app) {
            $config = $app['config']->get('runtime-guard.optimizer.fusion', []);
            return new GuardFusionOptimizer($config);
        });

        // Async Guard Executor
        $this->app->singleton(AsyncGuardExecutor::class, function ($app) {
            $config = $app['config']->get('runtime-guard.optimizer.async_executor', []);
            return new AsyncGuardExecutor($config);
        });

        // Incremental Inspector
        $this->app->singleton(IncrementalInspector::class, function ($app) {
            $config = $app['config']->get('runtime-guard.optimizer.incremental', []);
            return new IncrementalInspector($config);
        });

        // Resource Pool Manager
        $this->app->singleton(ResourcePoolManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.optimizer.resource_pool', []);
            return new ResourcePoolManager($config);
        });
    }

    /**
     * Register v4.0 developer tools.
     */
    protected function registerV4DevTools(): void
    {
        // Security Playground
        $this->app->singleton(SecurityPlayground::class, function ($app) {
            $config = $app['config']->get('runtime-guard.devtools.playground', []);
            return new SecurityPlayground($config);
        });

        // Guard Profiler
        $this->app->singleton(GuardProfiler::class, function ($app) {
            $config = $app['config']->get('runtime-guard.devtools.profiler', []);
            return new GuardProfiler($config);
        });

        // Rule Builder
        $this->app->singleton(RuleBuilder::class, function ($app) {
            return new RuleBuilder();
        });

        // Test Data Generator
        $this->app->singleton(TestDataGenerator::class, function ($app) {
            return new TestDataGenerator();
        });
    }

    /**
     * Register v4.0 multi-tenant components.
     */
    protected function registerV4MultiTenant(): void
    {
        // Tenant Isolation Manager
        $this->app->singleton(TenantIsolationManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.multi_tenant.isolation', []);
            return new TenantIsolationManager($config);
        });

        // Tenant Rule Engine
        $this->app->singleton(TenantRuleEngine::class, function ($app) {
            $config = $app['config']->get('runtime-guard.multi_tenant.rules', []);
            return new TenantRuleEngine($config);
        });

        // Cross-Tenant Intelligence
        $this->app->singleton(CrossTenantIntelligence::class, function ($app) {
            $config = $app['config']->get('runtime-guard.multi_tenant.intelligence', []);
            return new CrossTenantIntelligence($config);
        });

        // Tenant Quota Manager
        $this->app->singleton(TenantQuotaManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.multi_tenant.quotas', []);
            return new TenantQuotaManager($config);
        });
    }

    /**
     * Register v4.0 observability components.
     */
    protected function registerV4Observability(): void
    {
        // Real-Time Metrics Collector
        $this->app->singleton(RealTimeMetricsCollector::class, function ($app) {
            $config = $app['config']->get('runtime-guard.observability.metrics', []);
            return new RealTimeMetricsCollector($config);
        });

        // Threat Heatmap
        $this->app->singleton(ThreatHeatmap::class, function ($app) {
            $config = $app['config']->get('runtime-guard.observability.heatmap', []);
            return new ThreatHeatmap($config);
        });

        // Security Scorecard
        $this->app->singleton(SecurityScorecard::class, function ($app) {
            $config = $app['config']->get('runtime-guard.observability.scorecard', []);
            return new SecurityScorecard($config);
        });

        // Alert Correlator
        $this->app->singleton(AlertCorrelator::class, function ($app) {
            $config = $app['config']->get('runtime-guard.observability.alert_correlator', []);
            return new AlertCorrelator($config);
        });
    }

    /**
     * Register v4.0 advanced features.
     */
    protected function registerV4Advanced(): void
    {
        // Honeytoken Manager
        $this->app->singleton(HoneytokenManager::class, function ($app) {
            $config = $app['config']->get('runtime-guard.advanced.honeytokens', []);
            return new HoneytokenManager($config);
        });

        // Runtime Policy Engine
        $this->app->singleton(RuntimePolicyEngine::class, function ($app) {
            $config = $app['config']->get('runtime-guard.advanced.policies', []);
            return new RuntimePolicyEngine($config);
        });

        // WAF Rule Exporter
        $this->app->singleton(WafRuleExporter::class, function ($app) {
            $config = $app['config']->get('runtime-guard.advanced.waf_export', []);
            return new WafRuleExporter($config);
        });

        // Threat Intel Feed
        $this->app->singleton(ThreatIntelFeed::class, function ($app) {
            $config = $app['config']->get('runtime-guard.advanced.threat_intel', []);
            return new ThreatIntelFeed($config);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array<string>
     */
    public function provides(): array
    {
        return [
            // Core
            GuardManagerInterface::class,
            GuardManager::class,
            CorrelationEngine::class,
            ProgressiveEnforcement::class,
            FeatureFlagManager::class,
            ProfileResolver::class,
            LogReporter::class,
            DatabaseReporter::class,
            AsyncReporter::class,
            
            // Performance
            BloomFilter::class,
            JitWarmer::class,
            LazyGuardResolver::class,
            StreamingInspector::class,
            SharedMemoryStore::class,
            RequestFingerprint::class,
            RingBuffer::class,
            
            // Integrations
            TelescopeIntegration::class,
            PulseIntegration::class,
            OpenApiValidator::class,
            SiemConnector::class,
            
            // Analytics
            AttackFingerprinter::class,
            StixExporter::class,
            GeoIpCorrelator::class,
            TrendAnalyzer::class,
            ComplianceReporter::class,
            AttackChainReconstructor::class,
            RiskScoringEngine::class,
            
            // Resilience
            CircuitBreaker::class,
            LoadShedder::class,
            
            // Notifications
            WebhookDispatcher::class,
            
            // Plugins & Debug
            PluginManager::class,
            DebugExplainer::class,
            
            // v4.0 ML/AI
            MLAnomalyDetector::class,
            PatternLearningEngine::class,
            ThreatClassifier::class,
            AdaptiveThresholdManager::class,
            
            // v4.0 Performance Optimizers
            GuardFusionOptimizer::class,
            AsyncGuardExecutor::class,
            IncrementalInspector::class,
            ResourcePoolManager::class,
            
            // v4.0 DevTools
            SecurityPlayground::class,
            GuardProfiler::class,
            RuleBuilder::class,
            TestDataGenerator::class,
            
            // v4.0 Multi-Tenant
            TenantIsolationManager::class,
            TenantRuleEngine::class,
            CrossTenantIntelligence::class,
            TenantQuotaManager::class,
            
            // v4.0 Observability
            RealTimeMetricsCollector::class,
            ThreatHeatmap::class,
            SecurityScorecard::class,
            AlertCorrelator::class,
            
            // v4.0 Advanced
            HoneytokenManager::class,
            RuntimePolicyEngine::class,
            WafRuleExporter::class,
            ThreatIntelFeed::class,
            
            'runtime-guard',
        ];
    }
}
