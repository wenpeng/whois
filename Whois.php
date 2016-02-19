<?php
/**
 * Author: Wen Peng
 * Email: imwwp@outlook.com
 * Time: 2015/12/21 10:23
 */
class Whois
{
    private $domain;
    private $tld;
    private $sub;
    private $retry;

    public function query($domain, $retry = 0)
    {
        // 验证格式
        if (preg_match('/^([-a-z0-9]{2,100})\.([a-z\.]{2,8})$/i', $domain, $matches)) {
            // 设置变量
            $this->sub = strtolower($matches[1]);
            $this->tld = $matches[2];

            // 设置域名
            $this->domain = $this->sub . '.' . $this->tld;

            // 验证顶域
            $config = $this->server($this->tld);
            if (empty($config)) {
                // 返回消息
                $result = array(
                    'error' => 1,
                    'message' => "{$this->domain} 不支持的域名后缀"
                );
            } else {
                // 自动重试
                $this->retry = $retry;

                // 开始查询
                $result = $this->process($config);
            }
        } else {
            // 返回消息
            $result = array(
                'error' => 1,
                'message' => "{$domain} 域名格式不正确"
            );
        }

        // 返回结果
        return $result;
    }

    private function process($config, $retry = 0)
    {
        // 发起通信
        $socket = fsockopen($config['server'], 43);

        // 验证通信
        if ($socket === false) {
            // 是否重试
            if ($retry < $this->retry) {
                return $this->process($config, $retry + 1);
            } else {
                return array(
                    'error' => 1,
                    'message' => "{$config['server']} 服务器无法访问"
                );
            }
        }
        fputs($socket, "{$this->domain}\r\n");

        // 取出响应
        $response = '';
        while (!feof($socket)) {
            $response .= fgets($socket, 128);
        }

        // 关闭通信
        fclose($socket);

        // 转换编码
        $encoding = array('UTF-8','ISO-8859-1','ISO-8859-15','ASCII','CP936','EUC-CN','BIG-5','JIS','eucJP-win','SJIS-win','EUC-JP');
        $response = htmlspecialchars(mb_convert_encoding($response, 'UTF-8', mb_detect_encoding($response, $encoding, true)));

        // 生成结果
        if (stripos($response, $config['not_match']) === false) {
            $result = array(
                'domain' => $this->domain,
                'registration' => 'registered',
                'registrar' => preg_match($config['registrar'], $response, $registrar) ? $registrar[1] : '',
                'creation' => preg_match($config['creation'], $response, $creation) ? strtotime($creation[1]) : '',
                'expiration' => preg_match($config['expiration'], $response, $expiration) ? strtotime($expiration[1]) : '',
                'status' => preg_match($config['status'], $response, $status) ? $status[1] : '',
            );
        } else {
            $result = array(
                'domain' => $this->domain,
                'registration' => 'unregistered',
            );
        }

        // 返回结果
        return array(
            'error' => 0,
            'data' => $result
        );
    }

    private function server($tld)
    {
        // 匹配顶域
        switch ($tld) {
            case 'com':
            case 'net':
                $data = array(
                    'server' => 'whois.internic.net',
                    'not_match' => 'No match for',
                    'registrar' => '/Registrar:\s*(.*)/i',
                    'creation' => '/Creation Date:\s*(.*)/i',
                    'expiration' => '/Expiration Date:\s*(.*)/i',
                    'status' => '/Status:\s*(\w*)/i',
                );
                break;
            case 'org':
                $data = array(
                    'server' => 'whois.pir.org',
                    'not_match' => 'NOT FOUND',
                    'registrar' => '/Registrar:\s*(.*)/i',
                    'creation' => '/Creation Date:\s*(.*)/i',
                    'expiration' => '/Registry Expiry Date:\s*(.*)/i',
                    'status' => '/Domain Status:\s*(\w*)/i',
                );
                break;
            case 'cn':
            case 'com.cn':
            case 'net.cn':
            case 'org.cn':
                $data = array(
                    'server' => 'whois.cnnic.net.cn',
                    'not_match' => 'No matching record',
                    'registrar' => '/Sponsoring Registrar:\s*(.*)/i',
                    'creation' => '/Registration Time:\s*(.*)/i',
                    'expiration' => '/Expiration Time:\s*(.*)/i',
                    'status' => '/Domain Status:\s*(\w*)/i',
                );
                break;
            default:
                $data = array();
        }
        return $data;
    }
}
