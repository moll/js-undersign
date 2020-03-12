var O = require("oolong")
var egal = require("egal")
var deepEgal = require("egal").deepEgal

exports.each = O.each
exports.assign = O.assign
exports.defaults = O.defaults
exports.values = O.values
exports.mapValues = O.map
exports.mapKeys = O.mapKeys
exports.filterValues = O.filter
exports.merge = O.merge
exports.defineGetter = O.defineGetter
exports.compose = require("lodash.flowright")
exports.indexBy = require("lodash.indexby")
exports.max = function(array) { return Math.max.apply(null, array) }

exports.map = function(obj, fn) {
	if (typeof obj.length == "number") return obj.map(fn)

	var array = []
	for (var key in obj) array.push(fn(obj[key], key))
	return array
}

exports.fromEntries = function(array) {
	return array.reduce((obj, kv) => (obj[kv[0]] = kv[1], obj), {})
}

exports.pick = function(obj, keys) {
	return O.pick.apply(null, [obj].concat(keys))
}

exports.deepEquals = function(a, b) {
	return deepEgal(a, b, egalBuffer)
}

function egalBuffer(a, b) {
  if (egal(a, b)) return true

	var aType = typeOf(a)
	var bType = typeOf(b)
	if (aType != bType) return false

  switch (aType) {
    case "array":
    case "plain": return null
		case "buffer": return a.equals(b)
    default: return false
  }
}

function typeOf(obj) {
	if (obj === null) return "null"
	if (obj instanceof Array) return "array"
	if (obj instanceof Buffer) return "buffer"

  var type = typeof obj
  if (type == "object" && O.isPlainObject(obj)) return "plain"
  return type
}
