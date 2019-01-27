const { addColors, createLogger, format, transports } = require('winston');
const expressWinston = require('express-winston');
const moment = require('moment');

const { LOG_LEVEL } = require('../../config/env.config');

const LOG_LEVELS = {
  FATAL: 'fatal',
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug',
  TRACE: 'trace',
};
const { FATAL, ERROR, WARN, INFO, DEBUG, TRACE } = LOG_LEVELS;

addColors({
  [FATAL]: 'red',
  [ERROR]: 'red',
  [WARN]: 'yellow',
  [INFO]: 'white',
  [DEBUG]: 'blue',
  [TRACE]: 'blue',
});

const log = createLogger({
  levels: {
    [FATAL]: 1,
    [ERROR]: 2,
    [WARN]: 3,
    [INFO]: 4,
    [DEBUG]: 5,
    [TRACE]: 6,
  },
  format: format.combine(
    format.colorize(),
    format.timestamp(),
    format.printf(info => `${info.timestamp} - ${info.level}: ${info.message}`)
  ),
  transports: [
    new transports.Console({
      level: LOG_LEVEL,
      timestamp: () => moment().format(),
    }),
  ],
});

log.emitErrs = false;

function formatRequestMessage(req) {
  let msg = `${req.protocol.toUpperCase()} ${req.method} ${req.url}`;

  const body = JSON.stringify(req.body, null, 2);
  if (body) {
    msg += `\nbody: ${body}`;
  }

  return msg;
}

const requestLogger = expressWinston.logger({
  winstonInstance: log,
  msg: formatRequestMessage,
});

module.exports = {
  LOG_LEVELS,
  log,
  requestLogger,
};
