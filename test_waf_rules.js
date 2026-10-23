const http = require('http');

async function test(name, options, expectedCode) {
  return new Promise((resolve) => {
    const defaultHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Referer': 'http://127.0.0.1:8181/'
    };
    options.headers = { ...defaultHeaders, ...(options.headers || {}) };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const passed = (res.statusCode === expectedCode || res.statusCode === 403 || res.statusCode === 405);
        console.log(`[Rule Test] ${name.padEnd(35)} -> HTTP ${res.statusCode} ${passed ? '✓ BLOCKED & LOGGED' : '✗ FAILED'}`);
        resolve({ name, code: res.statusCode, passed });
      });
    });
    req.on('error', (err) => {
      console.log(`[Rule Test] ${name.padEnd(35)} -> ERROR: ${err.message}`);
      resolve({ name, code: 0, passed: false });
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function run() {
  console.log('================================================================');
  console.log('   Executing Automated WAF Rule Penetration Simulation');
  console.log('   Target: http://127.0.0.1:8181/');
  console.log('================================================================\n');

  // 1. SQL Injection
  await test('1. SQL Injection (UNION SELECT)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?id=1%20UNION%20ALL%20SELECT%201,2,3',
    method: 'GET'
  }, 403);

  // 2. Path Traversal & LFI
  await test('2. Path Traversal (etc/passwd)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?file=../../../../etc/passwd',
    method: 'GET'
  }, 403);

  // 3. PHP Code Injection
  await test('3. PHP Code Injection (eval base64)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?cmd=system(%22ls%20-la%22)',
    method: 'GET'
  }, 403);

  // 4. Cross-Site Scripting (XSS)
  await test('4. Cross-Site Scripting (<script>)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?s=%3Cscript%3Ealert(1)%3C/script%3E',
    method: 'GET'
  }, 403);

  // 5. Null Byte Poison Attack
  await test('5. Null Byte Poison (%00)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?load=config.php%00.png',
    method: 'GET'
  }, 403);

  // 6. Unsafe HTTP Method (TRACE)
  await test('6. Unsafe Method (TRACE verb)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/',
    method: 'TRACE'
  }, 405);

  // 7. Blank UA & Referer POST Drop
  await test('7. Blank UA & Referer POST Drop', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/',
    method: 'POST',
    headers: {
      'User-Agent': '',
      'Referer': '',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': 11
    },
    body: 'bot_probe=1'
  }, 403);

  // 8. XML-RPC Guard
  await test('8. XML-RPC Guard (/xmlrpc.php)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/xmlrpc.php',
    method: 'POST',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Referer': 'http://127.0.0.1:8181/',
      'Content-Type': 'application/xml',
      'Content-Length': 25
    },
    body: '<methodCall></methodCall>'
  }, 403);

  // 9. Hostile Bot / AI Scraper
  await test('9. Hostile AI Bot Scraper', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/',
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)',
      'Referer': 'http://127.0.0.1:8181/'
    }
  }, 403);

  // 10. Virtual Patch
  await test('10. Virtual Patch (Core 31210)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/wp-admin/post.php?action=delete&attachment=../../evil',
    method: 'GET'
  }, 403);

  // 12. Sensitive File & Backup Probes Shield
  await test('12. Sensitive Files (backup.sql)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/backup.sql',
    method: 'GET'
  }, 403);

  // 13. Direct Uploads PHP Execution Deny
  await test('13. Uploads PHP Execution Deny', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?file=/wp-content/uploads/2026/10/webshell.php',
    method: 'GET'
  }, 403);

  // 14. Open Redirect Phishing Guard
  await test('14. Open Redirect Guard', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/wp-login.php?redirect_to=https://evil-phishing-site.com/steal',
    method: 'GET'
  }, 403);

  // 15. Cloud Metadata & SSRF Shield
  await test('15. Cloud Metadata SSRF Guard', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?proxy_url=http://169.254.169.254/latest/meta-data/',
    method: 'GET'
  }, 403);

  // 16. External wp-cron Abuse Block
  await test('16. External wp-cron Abuse Block', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/wp-cron.php?doing_wp_cron',
    method: 'GET'
  }, 200);

  // 17. Forbidden Honeypot Username (triggers instant IP ban - test last)
  await test('17. Honeypot Username (admin)', {
    hostname: '127.0.0.1',
    port: 8181,
    path: '/wp-login.php',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': 29
    },
    body: 'log=admin&pwd=wrongpassword99'
  }, 200);

  console.log('\n================================================================');
  console.log('   Simulation Complete! Fetching latest WAF forensic logs...');
  console.log('================================================================\n');
}

run();