var qs;

qs = require('querystring');

module.exports = function(csrf_generator, cache, authentication) {
  return function(app) {
    app.get('/oauth/csrf_token', (function(_this) {
      return function(req, res) {
        var csrf_token;
        csrf_token = csrf_generator(req);
        return res.send(200, csrf_token);
      };
    })(this));
    return app.post('/oauth/authenticate', (function(_this) {
      return function(req, res) {
        return authentication.authenticate((qs.parse(req.body)).code, req).then(function(r) {
          return res.send(200, 'Successfully authenticated');
        }).fail(function(e) {
          return res.send(400, 'An error occured during authentication');
        });
      };
    })(this));
  };
};
