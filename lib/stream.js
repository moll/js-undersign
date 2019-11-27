var concatStream = require("concat-stream")

exports.slurp = function(stream, encoding) {
	return new Promise(function(resolve, reject) {
		if (encoding) stream.setEncoding(encoding)
		stream.pipe(concatStream(resolve))
		stream.on("error", reject)
	})
}
