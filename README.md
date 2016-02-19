# PHP-Whois
PHP-Whois是一个非常轻量级的域名whois信息查询类，具有部署简单和方便扩展的特点

# 需求
对低版本做了向下支持，但建议使用 PHP 5.3 +

# 用法
```php
$whois = new Whois;

$query = $whois->query(域名主体, 重试次数); 

// 成功
array(
    'error' => 0,
    'data' => array(
        'domain' => 域名主体,
        'registration' => 注册状态,
        // 以下只在已注册时有效
        'registrar' => 域名服务商,
        'creation' => 注册时间,
        'expiration' => 过期时间,
        'status' => 域名状态,
    )
);

// 失败
array(
    'error' => 1,
    'message' => 失败原因
);

```
#示例
```php
$whois = new Whois;

$query = $whois->query('v2ex.com', 3); 

var_dump($query);

array(
    'error' => 0,
    'data' => array(
        'domain' => 'v2ex.com',
        'registration' => 'registered',
        'registrar' => 'TUCOWS DOMAINS INC.',
        'creation' => '1119542400',
        'expiration' => '1466697600',
        'status' => 'clientTransferProhibited',
    )
);
```
