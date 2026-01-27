<?php
/**
 * MijAuth - JSON File Attempt Logger
 *
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth\Logging;

use RuntimeException;

/**
 * Append-only JSON Lines logger
 */
class JsonFileAttemptLogger implements AttemptLoggerInterface
{
    private string $filePath;

    public function __construct(string $filePath)
    {
        $this->filePath = $filePath;
    }

    public function logAttempt(array $context): void
    {
        if (!isset($context['logged_at'])) {
            $context['logged_at'] = date('c');
        }

        $line = json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($line === false) {
            throw new RuntimeException('Failed to encode log context');
        }

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
                throw new RuntimeException('Failed to create log directory');
            }
        }

        $result = file_put_contents($this->filePath, $line . PHP_EOL, FILE_APPEND | LOCK_EX);

        if ($result === false) {
            throw new RuntimeException('Failed to write log file');
        }
    }
}
