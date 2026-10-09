const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const PLUGIN_SLUG = 'wcp-security-scanner';
const PACKAGE_DIR = path.join(DIST_DIR, PLUGIN_SLUG);
const ZIP_FILE = path.join(ROOT_DIR, `${PLUGIN_SLUG}.zip`);

console.log('--- Packaging WCP Security Scanner for WordPress.org ---');

// 1. Clean dist directory and previous zip
if (fs.existsSync(DIST_DIR)) {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(PACKAGE_DIR, { recursive: true });

if (fs.existsSync(ZIP_FILE)) {
  fs.unlinkSync(ZIP_FILE);
}

// 2. Define files and folders to include
const includeFiles = [
  'wcp-wp-scanner.php',
  'readme.txt',
  'composer.json',
  'README.md',
];

const includeDirs = [
  'build',
  'includes',
  'languages',
];

// Helper to copy directory recursively, strictly ignoring dotfiles and dev files
function copyDirRecursive(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    // Strictly skip all hidden files/dirs (starting with '.')
    if (entry.name.startsWith('.')) {
      continue;
    }
    // Skip dev files, tests, map files if any
    if (entry.name === 'tests' || entry.name === 'node_modules' || entry.name.endsWith('.map')) {
      continue;
    }

    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// 3. Copy files
for (const file of includeFiles) {
  const src = path.join(ROOT_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, path.join(PACKAGE_DIR, file));
    console.log(`[Copied] ${file}`);
  } else {
    console.warn(`[Warning] Missing file: ${file}`);
  }
}

// 4. Copy folders
for (const dir of includeDirs) {
  const src = path.join(ROOT_DIR, dir);
  if (fs.existsSync(src)) {
    copyDirRecursive(src, path.join(PACKAGE_DIR, dir));
    console.log(`[Copied] ${dir}/`);
  } else {
    console.warn(`[Warning] Missing directory: ${dir}`);
  }
}

// 5. Verification checks
console.log('\n--- Running Validation Checks on Staged Package ---');

function scanForDotfiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.')) {
      throw new Error(`Forbidden hidden file found: ${path.join(dir, entry.name)}`);
    }
    if (entry.isDirectory()) {
      scanForDotfiles(path.join(dir, entry.name));
    }
  }
}
scanForDotfiles(PACKAGE_DIR);
console.log('✓ No hidden files found (clean of .gitignore, .git, etc.)');

// Verify languages folder is not empty
const langFiles = fs.readdirSync(path.join(PACKAGE_DIR, 'languages'));
if (langFiles.length === 0) {
  throw new Error('languages/ directory cannot be empty!');
}
console.log('✓ languages/ directory contains files:', langFiles.join(', '));

// Verify forbidden functions in staged files
function scanForForbiddenFunctions(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanForForbiddenFunctions(full);
    } else if (entry.name.endsWith('.php')) {
      const content = fs.readFileSync(full, 'utf8');
      // Strip comments and string literals to only check executable PHP function calls
      const executableCode = content
        .replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '')
        .replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, '');
      if (/\bstr_rot13\s*\(/i.test(executableCode)) {
        throw new Error(`Forbidden function str_rot13() found in: ${full}`);
      }
    }
  }
}
scanForForbiddenFunctions(PACKAGE_DIR);
console.log('✓ No forbidden functions (str_rot13) found');

// Verify unexpected root markdown files
const rootEntries = fs.readdirSync(PACKAGE_DIR);
for (const entry of rootEntries) {
  if (entry.endsWith('.md') && !['README.md', 'CHANGELOG.md'].includes(entry)) {
    throw new Error(`Unexpected markdown file in root: ${entry}`);
  }
}
console.log('✓ Root directory clean of unexpected markdown files');

// Verify Text Domain in wcp-wp-scanner.php
const mainPluginContent = fs.readFileSync(path.join(PACKAGE_DIR, 'wcp-wp-scanner.php'), 'utf8');
if (!/Text Domain:\s*wcp-security-scanner/.test(mainPluginContent)) {
  throw new Error('Text Domain header does not match slug: wcp-security-scanner');
}
console.log('✓ Text Domain header verified as wcp-security-scanner');

// 6. Create ZIP archive
console.log('\n--- Generating Release Archive ---');
try {
  // Use tar or powershell Compress-Archive
  execSync(`tar -a -cf "${ZIP_FILE}" -C "${DIST_DIR}" "${PLUGIN_SLUG}"`, { stdio: 'inherit' });
  console.log(`✓ Created: ${ZIP_FILE}`);
} catch (err) {
  console.log('tar fallback to PowerShell Compress-Archive...');
  execSync(`powershell -Command "Compress-Archive -Path '${PACKAGE_DIR}' -DestinationPath '${ZIP_FILE}' -Force"`, { stdio: 'inherit' });
  console.log(`✓ Created: ${ZIP_FILE}`);
}

// Clean up staging folder
fs.rmSync(DIST_DIR, { recursive: true, force: true });
console.log('\n--- Staging directory cleaned up. Package is ready for WordPress.org upload! ---');
