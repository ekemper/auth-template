// dependencies
require('dotenv').config();
const _ = require('lodash');

// local dependencies
const PACKAGE = require('../package.json');

const PROCESS_ENV = process.env;
const envConfig = {
  // general
  LOG_LEVEL: (PROCESS_ENV.LOG_LEVEL || 'info').toLowerCase(),
  REPO_NAME: PACKAGE.name,
  VERSION: PACKAGE.version,
  PORT: PROCESS_ENV.PORT || 4001,
  // environments
  LOCAL: 'LOCAL',
  TEST: 'TEST',
  PROD: 'PROD',
};

_.assign(envConfig);

module.exports = envConfig;
