module.exports = {
  extends: ['codfish'],
  rules: {
    'no-underscore-dangle': 'off',
    'no-console': 'off',
    'import/extensions': 'off',
    'no-restricted-syntax': 'off',
    'no-plusplus': 'off',
    'func-names': 'off',
  },
  globals: {
    BigInt: 'true',
  },
  env: {
    mocha: true,
  },
};
