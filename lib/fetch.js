var fetch = require("fetch-off")

// RIA's Mobile-ID and Smart-ID proxy doesn't permit chunked requests, so ensure
// the Content-Length header is set.
fetch = require("./fetch/fetch_content_length")(fetch)

fetch = require("fetch-jsonify")(fetch)

fetch = require("fetch-parse")(fetch, {
	json: true,
	"application/ocsp-response": parseBuffer,
	"application/timestamp-reply": parseBuffer
})

fetch = require("fetch-throw")(fetch)
module.exports = fetch

function parseBuffer(res) { return res.arrayBuffer().then(Buffer.from) }
