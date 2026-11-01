<?php

declare(strict_types=1);

/**
 * @package     Localzet SOCKS5
 * @link        https://github.com/localzet/SOCKS5
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright © 2016-2026 Localzet Group. All rights reserved.
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 *
 *              This program is free software: you can redistribute it and/or modify
 *              it under the terms of the GNU Affero General Public License as published
 *              by the Free Software Foundation, either version 3 of the License, or
 *              (at your option) any later version.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *              GNU Affero General Public License for more details.
 *
 *              You should have received a copy of the GNU Affero General Public License
 *              along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 *              For any questions, please contact <creator@localzet.com>
*/


$bindAddress = getenv('SOCKS5_BIND') ?: '127.0.0.1';
$username = getenv('SOCKS5_USERNAME');
$password = getenv('SOCKS5_PASSWORD');
$anonymous = getenv('SOCKS5_ALLOW_NO_AUTH') === '1';
$port = filter_var(getenv('SOCKS5_PORT') ?: '1080', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 65535],
]);
$maxConnections = filter_var(getenv('SOCKS5_MAX_CONNECTIONS') ?: '1024', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 100000],
]);
$maxConnectionsPerIp = filter_var(getenv('SOCKS5_MAX_CONNECTIONS_PER_IP') ?: '32', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 10000],
]);
$maxAttemptsPerMinute = filter_var(getenv('SOCKS5_MAX_ATTEMPTS_PER_MINUTE') ?: '120', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 100000],
]);
if (!filter_var($bindAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $port === false ||
    $maxConnections === false || $maxConnectionsPerIp === false || $maxAttemptsPerMinute === false) {
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
    'max_connections' => $maxConnections,
    'max_connections_per_ip' => $maxConnectionsPerIp,
    'max_attempts_per_minute' => $maxAttemptsPerMinute,
    'tcp_port' => $port,
    'udp_enabled' => false,
    'udp_port' => 0,
    'wanIP' => $bindAddress,
];
