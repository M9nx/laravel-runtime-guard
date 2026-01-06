<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('runtime_guard_events', function (Blueprint $table) {
            $table->id();
            $table->string('guard_name', 64)->index();
            $table->string('threat_level', 16)->index();
            $table->text('message');
            $table->json('details')->nullable();
            $table->json('context')->nullable();

            // Request information
            $table->string('ip_address', 45)->nullable()->index();
            $table->string('user_agent', 512)->nullable();
            $table->string('request_uri', 2048)->nullable();
            $table->string('request_method', 10)->nullable();
            $table->string('route_name', 255)->nullable()->index();

            // User information
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->string('session_id', 128)->nullable()->index();

            // Correlation
            $table->string('correlation_id', 64)->nullable()->index();
            $table->string('input_hash', 64)->nullable()->index();

            // Response action
            $table->string('action_taken', 32)->nullable();

            $table->timestamps();

            // Composite indexes for common queries
            $table->index(['ip_address', 'created_at']);
            $table->index(['user_id', 'created_at']);
            $table->index(['guard_name', 'threat_level', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('runtime_guard_events');
    }
};
