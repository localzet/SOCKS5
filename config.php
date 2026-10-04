<?php

declare(strict_types=1);

$bindAddress = getenv('SOCKS5_BIND') ?: '127.0.0.1';
$username = getenv('SOCKS5_USERNAME');
$password = getenv('SOCKS5_PASSWORD');
$anonymous = getenv('SOCKS5_ALLOW_NO_AUTH') === '1';
$port = filter_var(getenv('SOCKS5_PORT') ?: '1080', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 65535],
]);
if (!filter_var($bindAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $port === false) {
    throw new RuntimeException('Invalid SOCKS bind address or port');
}
if ($anonymous && !str_starts_with($bindAddress, '127.')) {
    throw new RuntimeException('Anonymous SOCKS is restricted to loopback');
}
if (!$anonymous && ($username === false || $username === '' || $password === false || $password === '' ||
    strlen($username) > 255 || strlen($password) > 255)) {
    throw new RuntimeException('Set SOCKS5_USERNAME and SOCKS5_PASSWORD before starting');
}
$config = [
    'auth' => $anonymous ? [METHOD_NO_AUTH => true] : [
        METHOD_USER_PASS => static fn (array $request): bool =>
            hash_equals($username, $request['user']) && hash_equals($password, $request['pass']),
    ],
    'bind_address' => $bindAddress,
    'log_level' => LOG_INFO,
    'tcp_port' => $port,
    'udp_enabled' => false,
    'udp_port' => 0,
    'wanIP' => $bindAddress,
];
