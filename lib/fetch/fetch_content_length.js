var _ = require("../underscore")

exports = module.exports = function(fetch) {
  return _.assign(exports.fetch.bind(null, fetch), fetch)
}

exports.fetch = function(fetch, url, opts) {
  if (opts && opts.body !== undefined) opts = withContentLength(opts)
  return fetch(url, opts)
}

function withContentLength(opts) {
  return _.defaults({
		headers: _.assign({
			"Content-Length": Buffer.byteLength(opts.body)
		}, opts.headers)
  }, opts)
}
