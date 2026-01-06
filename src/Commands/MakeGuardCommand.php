<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Commands;

use Illuminate\Console\GeneratorCommand;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputOption;

#[AsCommand(name: 'runtime-guard:make-guard')]
class MakeGuardCommand extends GeneratorCommand
{
    protected $name = 'runtime-guard:make-guard';
    protected $description = 'Create a new RuntimeGuard guard class';
    protected $type = 'Guard';

    protected function getStub(): string
    {
        if ($this->option('anomaly')) {
            return $this->resolveStubPath('/stubs/guard.anomaly.stub');
        }

        if ($this->option('api')) {
            return $this->resolveStubPath('/stubs/guard.api.stub');
        }

        return $this->resolveStubPath('/stubs/guard.stub');
    }

    protected function resolveStubPath(string $stub): string
    {
        $customPath = $this->laravel->basePath(trim($stub, '/'));

        if (file_exists($customPath)) {
            return $customPath;
        }

        return __DIR__ . '/../../' . $stub;
    }

    protected function getDefaultNamespace($rootNamespace): string
    {
        return $rootNamespace . '\\Guards';
    }

    protected function buildClass($name): string
    {
        $stub = parent::buildClass($name);

        return $this->replaceGuardName($stub, $this->getNameInput());
    }

    protected function replaceGuardName(string $stub, string $name): string
    {
        $guardName = strtolower(preg_replace('/Guard$/', '', $name));
        $guardName = preg_replace('/(?<!^)[A-Z]/', '-$0', $guardName);
        $guardName = strtolower($guardName);

        return str_replace(
            ['{{ guardName }}', '{{guardName}}'],
            $guardName,
            $stub
        );
    }

    protected function getOptions(): array
    {
        return [
            ['anomaly', 'a', InputOption::VALUE_NONE, 'Create an anomaly-detection style guard'],
            ['api', null, InputOption::VALUE_NONE, 'Create an API-focused guard'],
            ['force', 'f', InputOption::VALUE_NONE, 'Overwrite existing guard'],
        ];
    }
}
