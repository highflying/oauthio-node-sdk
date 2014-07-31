var cache, package_info, _authentication, _csrf_generator, _endpoints_initializer, _guid, _requestio;

_guid = require('./tools/guid');

_csrf_generator = require('./lib/csrf_generator');

_endpoints_initializer = require('./lib/endpoints');

_authentication = require('./lib/authentication');

_requestio = require('./lib/request');

package_info = require('../package.json');

cache = {
  public_key: void 0,
  secret_key: void 0,
  csrf_tokens: [],
  oauthd_url: 'https://oauth.io'
};

module.exports = function() {
  var authentication, csrf_generator, endpoints_initializer, guid, requestio;
  guid = _guid();
  csrf_generator = _csrf_generator(guid);
  requestio = _requestio(cache);
  authentication = _authentication(cache, requestio);
  endpoints_initializer = _endpoints_initializer(csrf_generator, cache, authentication);
  return {
    initialize: function(app_public_key, app_secret_key) {
      cache.public_key = app_public_key;
      return cache.secret_key = app_secret_key;
    },
    __getCache: function() {
      return cache;
    },
    __clearCache: function() {
      return cache = {
        public_key: void 0,
        secret_key: void 0,
        csrf_tokens: [],
        oauthd_url: 'https://oauth.io'
      };
    },
    getAppKey: function() {
      return cache.public_key;
    },
    getAppSecret: function() {
      return cache.secret_key;
    },
    getCsrfTokens: function(session) {
      return session.csrf_tokens;
    },
    setOAuthdUrl: function(url) {
      return cache.oauthd_url = url;
    },
    getOAuthdUrl: function() {
      return cache.oauthd_url;
    },
    getVersion: function() {
      return package_info.version;
    },
    generateStateToken: function(session) {
      return csrf_generator(session);
    },
    initEndpoints: function(app) {
      return endpoints_initializer(app);
    },
    auth: function(provider, session, opts) {
      return authentication.auth(provider, session, opts);
    },
    refreshCredentials: function(credentials, session) {
      return authentication.refresh_tokens(credentials, session, true);
    }
  };
};
