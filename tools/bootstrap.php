<?php

declare(strict_types=1);

/*
 * Shared pieces of the functional test tools (not part of the library):
 *  - a file-based PSR-16 cache, shared by the PHP built-in server processes like Redis would be;
 *  - a curl-based PSR-18 client;
 *  - the state directory (.rg-test/ by default, RG_STATE to change it).
 */

namespace GuillaumeTissier\ResourceGuard\Tools;

use GuillaumeTissier\ResourceGuard\Util\Json;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;

require __DIR__.'/../vendor/autoload.php';

function state(string $file = ''): string
{
    $dir = getenv('RG_STATE') ?: __DIR__.'/../.rg-test';
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    return rtrim($dir, '/').('' === $file ? '' : '/'.$file);
}

/**
 * @return array<string, mixed> empty when the file does not exist
 */
function readJson(string $file): array
{
    $path = state($file);

    return is_file($path) ? Json::object(json_decode((string) file_get_contents($path), true)) ?? [] : [];
}

/**
 * $data[$key] as a string ('' when absent or not a string).
 */
function str(mixed $data, string $key): string
{
    $value = \is_array($data) ? ($data[$key] ?? null) : null;

    return \is_string($value) ? $value : '';
}

/**
 * @return array<string, mixed>
 */
function obj(mixed $data, string $key): array
{
    return Json::object(\is_array($data) ? ($data[$key] ?? null) : null) ?? [];
}

function writeJson(string $file, mixed $data): void
{
    file_put_contents(state($file), json_encode($data, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES), \LOCK_EX);
}

final class FileCache implements CacheInterface
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $file = $this->file($key);
        if (!is_file($file)) {
            return $default;
        }
        $entry = unserialize((string) file_get_contents($file));
        if (!\is_array($entry) || 2 !== \count($entry)) {
            return $default;
        }
        [$expiresAt, $value] = $entry;
        if (\is_int($expiresAt) && $expiresAt < time()) {
            @unlink($file);

            return $default;
        }

        return $value;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $expiresAt = match (true) {
            null === $ttl => null,
            $ttl instanceof \DateInterval => (new \DateTimeImmutable())->add($ttl)->getTimestamp(),
            default => time() + $ttl,
        };

        return false !== file_put_contents($this->file($key), serialize([$expiresAt, $value]), \LOCK_EX);
    }

    public function delete(string $key): bool
    {
        @unlink($this->file($key));

        return true;
    }

    public function clear(): bool
    {
        array_map('unlink', glob($this->directory.'/*') ?: []);

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->get($key, $default);
        }
    }

    /**
     * @param iterable<string, mixed> $values
     */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return null !== $this->get($key);
    }

    private function file(string $key): string
    {
        return $this->directory.'/'.hash('sha256', $key);
    }
}

final class CurlClient implements ClientInterface
{
    private Psr17Factory $factory;

    public function __construct()
    {
        $this->factory = new Psr17Factory();
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                $headers[] = $name.': '.$value;
            }
        }
        $responseHeaders = [];
        $ch = curl_init((string) $request->getUri());
        curl_setopt_array($ch, [
            \CURLOPT_CUSTOMREQUEST => $request->getMethod() ?: 'GET',
            \CURLOPT_RETURNTRANSFER => true,
            \CURLOPT_HTTPHEADER => $headers,
            \CURLOPT_TIMEOUT => 10,
            \CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$responseHeaders): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $responseHeaders[trim($name)][] = trim($value);
                }

                return \strlen($line);
            },
        ]);
        $body = (string) $request->getBody();
        if ('' !== $body) {
            curl_setopt($ch, \CURLOPT_POSTFIELDS, $body);
        }
        $content = curl_exec($ch);
        if (false === $content) {
            $error = curl_error($ch);
            throw new class($error, $request) extends \RuntimeException implements NetworkExceptionInterface {
                public function __construct(string $message, private RequestInterface $request)
                {
                    parent::__construct($message);
                }

                public function getRequest(): RequestInterface
                {
                    return $this->request;
                }
            };
        }
        $response = $this->factory->createResponse((int) curl_getinfo($ch, \CURLINFO_RESPONSE_CODE));
        foreach ($responseHeaders as $name => $values) {
            $response = $response->withHeader($name, $values);
        }

        return $response->withBody($this->factory->createStream((string) $content));
    }
}
