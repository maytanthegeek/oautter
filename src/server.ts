/* eslint-disable import/first */
/* eslint-disable no-console */
require('dotenv').config();

import config from './config';
import server from './app';

/**
 * Start Express server.
 */
server.app.listen(config.PORT, () => {
  console.log(
    '  App is running at http://localhost:%d in %s mode',
    config.PORT,
    config.ENV,
  );
  console.log('  Press CTRL-C to stop\n');
});
