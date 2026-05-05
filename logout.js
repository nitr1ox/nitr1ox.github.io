// netlify/functions/logout.js
const { clearSessionCookie } = require('./_utils');

exports.handler = async () => {
  return {
    statusCode: 302,
    headers: {
      Location:     '/',
      'Set-Cookie': clearSessionCookie()
    },
    body: ''
  };
};
