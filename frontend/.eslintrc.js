module.exports = {
  root: true,
  env: {
    node: true
  },
  extends: ['plugin:vue/essential', '@vue/standard', '@vue/airbnb', 'plugin:prettier/recommended'],
  rules: {
    'no-console': process.env.NODE_ENV === 'production' ? 'error' : 'off',
    'no-debugger': process.env.NODE_ENV === 'production' ? 'error' : 'off',
    'linebreak-style': "unix",
    'import/no-unresolved': false,
    'import/extensions': false
  },
  parserOptions: {
    parser: 'babel-eslint'
  }
}