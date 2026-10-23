const http = require('http');
const { execSync } = require('child_process');

function request(options, body) {
  return new Promise((resolve) => {
    const defaultHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Host': 'localhost:8181'
    };
    options.headers = { ...defaultHeaders, ...(options.headers || {}) };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, data });
      });
    });
    req.on('error', (err) => {
      resolve({ statusCode: 0, error: err.message });
    });
    if (body) req.write(body);
    req.end();
  });
}

function getLatestLogs(limit = 5) {
  try {
    const cmd = `docker exec local-wordpress wp db query "SELECT id, ip_address, rule_category, LEFT(rule_description, 60) as description, action_taken, http_status_code FROM wp_wcpscan_firewall_logs ORDER BY id DESC LIMIT ${limit};" --path=/var/www/html --allow-root`;
    const out = execSync(cmd, { encoding: 'utf8' });
    return out.trim();
  } catch (e) {
    return 'Error querying logs: ' + e.message;
  }
}

async function runLiveHttpSimulations() {
  console.log('====================================================================');
  console.log('   WCP Security Scanner - Live HTTP Smart Rules Penetration Test');
  console.log('   Target: http://127.0.0.1:8181/');
  console.log('====================================================================\n');

  console.log('--- TEST 1: Empty UA & Referer POST (Commerce Safe vs Regular) ---');
  // Scenario A: Without Commerce Header (Should be blocked by Rule: Blank UA & Referer)
  const emptyPostAttacker = await request({
    hostname: '127.0.0.1',
    port: 8181,
    path: '/',
    method: 'POST',
    headers: {
      'User-Agent': '',
      'Referer': '',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }, 'probe=1');
  console.log(`[HTTP Live] Unauthenticated Empty UA POST -> Status: ${emptyPostAttacker.statusCode} (Expected: 403 Forbidden)`);

  // Scenario B: With Stripe-Signature Header (Payment Webhook Simulation)
  const stripeWebhook = await request({
    hostname: '127.0.0.1',
    port: 8181,
    path: '/wp-json/stripe/webhook',
    method: 'POST',
    headers: {
      'User-Agent': '',
      'Referer': '',
      'Stripe-Signature': 't=1600000000,v1=5257a869e7eceeda32af',
      'Content-Type': 'application/json'
    }
  }, JSON.stringify({ event: 'payment_intent.succeeded' }));
  console.log(`[HTTP Live] Stripe Webhook (No UA/Referer) -> Status: ${stripeWebhook.statusCode} (Expected: Non-403 WAF Pass)`);

  console.log('\n--- TEST 2: XML-RPC Jetpack Sync Attack vs Authentic Sync ---');
  // Scenario A: Standard XMLRPC Probe (waf_disable_xmlrpc is true by default)
  const attackerXmlrpc = await request({
    hostname: '127.0.0.1',
    port: 8181,
    path: '/xmlrpc.php',
    method: 'POST',
    headers: {
      'Content-Type': 'application/xml'
    }
  }, '<methodCall><methodName>system.listMethods</methodName></methodCall>');
  console.log(`[HTTP Live] Standard Attacker /xmlrpc.php -> Status: ${attackerXmlrpc.statusCode} (Expected: 403 Forbidden)`);

  // Scenario B: Attacker trying to spoof ?for=jetpack from non-Automattic IP
  const spoofedJetpack = await request({
    hostname: '127.0.0.1',
    port: 8181,
    path: '/xmlrpc.php?for=jetpack&timestamp=123456&signature=fake',
    method: 'POST',
    headers: {
      'Content-Type': 'application/xml'
    }
  }, '<methodCall><methodName>jetpack.test</methodName></methodCall>');
  console.log(`[HTTP Live] Spoofed /xmlrpc.php?for=jetpack from Local IP -> Status: ${spoofedJetpack.statusCode} (Expected: 403 Forbidden)`);

  console.log('\n--- TEST 3: Fake Uptime Monitor Spoofing ---');
  // Attacker claiming to be UptimeRobot User Agent on sensitive target
  const fakeUptime = await request({
    hostname: '127.0.0.1',
    port: 8181,
    path: '/?id=1%20UNION%20SELECT%201,2,3',
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)'
    }
  });
  console.log(`[HTTP Live] Fake Uptime UA with SQLi Payload -> Status: ${fakeUptime.statusCode} (Expected: 403 Forbidden)`);

  console.log('\n====================================================================');
  console.log('   Recent Intercepted Incidents in wp_wcpscan_firewall_logs:');
  console.log('====================================================================');
  console.log(getLatestLogs(6));
  console.log('\n====================================================================\n');
}

runLiveHttpSimulations();
