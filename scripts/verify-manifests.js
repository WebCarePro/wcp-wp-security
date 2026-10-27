const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

console.log('--- WCP Manifest Uniformity & Version Synchronization Verification ---');

const errors = [];
const versions = {};
const compatibility = {};

// 1. Check wcp-wp-scanner.php
const mainPhpPath = path.join(ROOT_DIR, 'wcp-wp-scanner.php');
if (fs.existsSync(mainPhpPath)) {
  const content = fs.readFileSync(mainPhpPath, 'utf8');
  const headerVerMatch = content.match(/\*\s*Version:\s*([0-9]+\.[0-9]+\.[0-9]+)/i);
  const constVerMatch = content.match(/define\(\s*['"]WCPSCAN_VERSION['"]\s*,\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]\s*\)/i);
  const reqWpMatch = content.match(/\*\s*Requires at least:\s*([0-9]+\.[0-9]+)/i);
  const reqPhpMatch = content.match(/\*\s*Requires PHP:\s*([0-9]+\.[0-9]+)/i);

  if (headerVerMatch) versions['wcp-wp-scanner.php (Header)'] = headerVerMatch[1];
  else errors.push('wcp-wp-scanner.php: Missing or invalid Version header');

  if (constVerMatch) versions['wcp-wp-scanner.php (Constant)'] = constVerMatch[1];
  else errors.push('wcp-wp-scanner.php: Missing or invalid WCPSCAN_VERSION define');

  if (reqWpMatch) compatibility['wcp-wp-scanner.php (Requires at least)'] = reqWpMatch[1];
  if (reqPhpMatch) compatibility['wcp-wp-scanner.php (Requires PHP)'] = reqPhpMatch[1];
} else {
  errors.push('wcp-wp-scanner.php not found');
}

// 2. Check readme.txt
const readmeTxtPath = path.join(ROOT_DIR, 'readme.txt');
if (fs.existsSync(readmeTxtPath)) {
  const content = fs.readFileSync(readmeTxtPath, 'utf8');
  const stableMatch = content.match(/Stable tag:\s*([0-9]+\.[0-9]+\.[0-9]+)/i);
  const reqWpMatch = content.match(/Requires at least:\s*([0-9]+\.[0-9]+)/i);
  const reqPhpMatch = content.match(/Requires PHP:\s*([0-9]+\.[0-9]+)/i);

  if (stableMatch) versions['readme.txt (Stable tag)'] = stableMatch[1];
  else errors.push('readme.txt: Missing or invalid Stable tag');

  if (reqWpMatch) compatibility['readme.txt (Requires at least)'] = reqWpMatch[1];
  if (reqPhpMatch) compatibility['readme.txt (Requires PHP)'] = reqPhpMatch[1];
} else {
  errors.push('readme.txt not found');
}

// 3. Check package.json
const packageJsonPath = path.join(ROOT_DIR, 'package.json');
if (fs.existsSync(packageJsonPath)) {
  try {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    if (pkg.version) versions['package.json'] = pkg.version;
    else errors.push('package.json: Missing version field');
  } catch (e) {
    errors.push(`package.json parsing error: ${e.message}`);
  }
} else {
  errors.push('package.json not found');
}

// 4. Check version.json
const versionJsonPath = path.join(ROOT_DIR, 'version.json');
if (fs.existsSync(versionJsonPath)) {
  try {
    const vj = JSON.parse(fs.readFileSync(versionJsonPath, 'utf8'));
    if (vj.version) versions['version.json'] = vj.version;
    else errors.push('version.json: Missing version field');

    if (vj.requires_wp) compatibility['version.json (requires_wp)'] = vj.requires_wp;
    if (vj.requires_php) compatibility['version.json (requires_php)'] = vj.requires_php;
  } catch (e) {
    errors.push(`version.json parsing error: ${e.message}`);
  }
} else {
  errors.push('version.json not found');
}

// 5. Check README.md
const readmeMdPath = path.join(ROOT_DIR, 'README.md');
if (fs.existsSync(readmeMdPath)) {
  const content = fs.readFileSync(readmeMdPath, 'utf8');
  const badgeMatch = content.match(/Release-v([0-9]+\.[0-9]+\.[0-9]+)/i);
  if (badgeMatch) versions['README.md (Badge)'] = badgeMatch[1];
  else errors.push('README.md: Missing Release-v badge');
} else {
  errors.push('README.md not found');
}

// 6. Check changelog.txt top entry
const changelogPath = path.join(ROOT_DIR, 'changelog.txt');
if (fs.existsSync(changelogPath)) {
  const content = fs.readFileSync(changelogPath, 'utf8');
  const topMatch = content.match(/v:([0-9]+\.[0-9]+\.[0-9]+)\s*-\s*([0-9]{4}-[0-9]{2}-[0-9]{2})/i);
  if (topMatch) {
    versions['changelog.txt (Top Entry)'] = topMatch[1];
  } else {
    errors.push('changelog.txt: Missing or invalid top version entry (expected e.g. v:1.28.0 - YYYY-MM-DD)');
  }
} else {
  errors.push('changelog.txt not found');
}

// Summary evaluation
console.log('\n--- Version Declarations Extracted ---');
for (const [source, ver] of Object.entries(versions)) {
  console.log(`  ${source}: ${ver}`);
}

const uniqueVersions = [...new Set(Object.values(versions))];
if (uniqueVersions.length > 1) {
  errors.push(`Version drift detected! Found multiple versions across manifests: ${uniqueVersions.join(', ')}`);
}

console.log('\n--- Minimum Compatibility Floats ---');
for (const [source, val] of Object.entries(compatibility)) {
  console.log(`  ${source}: ${val}`);
}

// Verify WP compatibility consistency
const wpFloors = [
  compatibility['wcp-wp-scanner.php (Requires at least)'],
  compatibility['readme.txt (Requires at least)'],
  compatibility['version.json (requires_wp)'],
].filter(Boolean);
if (new Set(wpFloors).size > 1) {
  errors.push(`WordPress compatibility floor mismatch: ${wpFloors.join(', ')}`);
}

// Verify PHP compatibility consistency
const phpFloors = [
  compatibility['wcp-wp-scanner.php (Requires PHP)'],
  compatibility['readme.txt (Requires PHP)'],
  compatibility['version.json (requires_php)'],
].filter(Boolean);
if (new Set(phpFloors).size > 1) {
  errors.push(`PHP compatibility floor mismatch: ${phpFloors.join(', ')}`);
}

if (errors.length > 0) {
  console.error('\n❌ Manifest Uniformity Check FAILED with errors:');
  errors.forEach(err => console.error(`  - ${err}`));
  process.exit(1);
}

console.log(`\n✅ All manifests are synchronized at version ${uniqueVersions[0]} (WP ${wpFloors[0] || '6.0'}+, PHP ${phpFloors[0] || '8.0'}+)!`);
