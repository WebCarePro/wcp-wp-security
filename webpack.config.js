const defaultConfig = require('@wordpress/scripts/config/webpack.config');
const path = require('path');

module.exports = {
  ...defaultConfig,
  entry: {
    'global': path.resolve(__dirname, 'src/entries/global.ts'),
    'index': path.resolve(__dirname, 'src/index.tsx'),
    'firewall': path.resolve(__dirname, 'src/entries/firewall.tsx'),
    'waf-logs': path.resolve(__dirname, 'src/entries/waf-logs.tsx'),
    'auth': path.resolve(__dirname, 'src/entries/auth.tsx'),
    'vault': path.resolve(__dirname, 'src/entries/vault.tsx'),
    'fim': path.resolve(__dirname, 'src/entries/fim.tsx'),
    'settings': path.resolve(__dirname, 'src/entries/settings.tsx'),
  },
  output: {
    ...defaultConfig.output,
    filename: '[name].js',
    path: path.resolve(__dirname, 'build'),
  },
};
