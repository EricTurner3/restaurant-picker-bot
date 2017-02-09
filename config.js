'use strict';

const APP_SECRET = process.env.APP_SECRET;
if (!APP_SECRET) {
  throw new Error('Missing APP_SECRET. Go to https://developers.facebook.com/ to get one.')
}


var PAGE_ACCESS_TOKEN = process.env.PAGE_ACCESS_TOKEN;
if (!PAGE_ACCESS_TOKEN) {
	throw new Error('Missing PAGE_ACCESS_TOKEN. Go to https://developers.facebook.com/docs/pages/access-tokens to get one.')
}

var VALIDATION_TOKEN = process.env.VALIDATION_TOKEN;

var SERVER_URL = process.env.SERVER_URL;

//mySQL Variables

var databaseHost = process.env.databaseHost;
var databaseUser = process.env.databaseUser;
var databasePass = process.env.databasePass;

module.exports = {
  APP_SECRET: APP_SECRET,
  PAGE_ACCESS_TOKEN: PAGE_ACCESS_TOKEN,
  VALIDATION_TOKEN: VALIDATION_TOKEN,
  SERVER_URL:SERVER_URL,
  databaseHost:databaseHost,
  databaseUser:databaseUser,
  databasePass:databasePass
}